"""
Copyright (c) 2025-2026, WSO2 LLC. (https://www.wso2.com).
WSO2 LLC. licenses this file to you under the Apache License,
Version 2.0 (the "License"); you may not use this file except
in compliance with the License.
You may obtain a copy of the License at
    http://www.apache.org/licenses/LICENSE-2.0
Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied. See the License for the
specific language governing permissions and limitations
under the License.
"""

"""Agent-enhanced OAuth2 authentication manager for Asgardeo AI."""

import asyncio
import logging
import base64
import os
import time
from typing import Callable, Dict, List, Literal, Optional, Tuple, Any
from urllib.parse import urlencode
from dataclasses import dataclass

from asgardeo import (
    AsgardeoConfig,
    OAuthToken,
    FlowStatus,
    AsgardeoNativeAuthClient,
    AsgardeoTokenClient,
    AuthenticationError,
    CIBAAuthenticationError,
    CIBAResponse,
    CIBAStatus,
    TokenError,
    ValidationError,
    generate_pkce_pair,
    generate_state,
    build_authorization_url
)

logger = logging.getLogger(__name__)

OrgDiscoveryType = Literal["orgID", "orgHandle", "org", "emailDomain"]


@dataclass
class AgentConfig:
    """Configuration for AI agent authentication."""
    
    agent_id: str
    agent_secret: str

class AgentAuthManager:
    """Agent-enhanced OAuth2 authentication manager for AI agents."""
    
    def __init__(
        self,
        config: AsgardeoConfig,
        agent_config: Optional[AgentConfig] = None,
        authorization_timeout: int = 300,
    ):
        """Initialize the agent auth manager.
        
        :param config: Asgardeo configuration
        :param agent_config: Optional agent-specific configuration
        :param authorization_timeout: Timeout for authorization operations
        """
        self.config = config
        self.agent_config = agent_config
        self.authorization_timeout = authorization_timeout
        self.token_client = AsgardeoTokenClient(config)

    async def get_agent_token(self, scopes: Optional[List[str]] = None) -> OAuthToken:
        """Get access token for the AI agent using agent credentials.
        
        :param scopes: List of OAuth scopes to request
        :return: OAuth token for the agent
        """
        if not self.agent_config:
            raise ValidationError("Agent configuration is required for agent authentication.")
        
        try:
            async with AsgardeoNativeAuthClient(self.config) as native_client:
                # Set custom scope if provided
                if scopes:
                    # Note: We need to modify the config temporarily
                    original_scope = self.config.scope
                    self.config.scope = ' '.join(scopes)
                
                # Start authentication flow
                code_verifier, code_challenge = generate_pkce_pair()
                params = {
                    "code_challenge": code_challenge,
                    "code_challenge_method": "S256",
                }
                init_response = await native_client.authenticate(params=params)
                
                if native_client.flow_status == FlowStatus.SUCCESS_COMPLETED:
                    auth_data = init_response.get('authData', {})
                elif native_client.flow_status == FlowStatus.INCOMPLETE:
                    # Find username/password authenticator
                    authenticators = native_client.next_step.get('authenticators', [])
                    username_auth = next(
                        (auth for auth in authenticators
                         if auth.get('authenticator') in ['Username & Password']),
                        None
                    )
                    if not username_auth:
                        raise AuthenticationError("No username/password authenticator found.")
                    
                    # Authenticate with agent credentials
                    auth_response = await native_client.authenticate(
                        authenticator_id=username_auth['authenticatorId'],
                        params={
                            'username': self.agent_config.agent_id,
                            'password': self.agent_config.agent_secret
                        }
                    )
                    
                    if native_client.flow_status == FlowStatus.SUCCESS_COMPLETED:
                        auth_data = auth_response.get('authData', {})
                    else:
                        raise AuthenticationError(f"Agent authentication failed with status: {native_client.flow_status}")
                else:
                    raise AuthenticationError(f"Unexpected authentication status: {native_client.flow_status}")

                code = auth_data.get('code')
                if not code:
                    raise TokenError("No authorization code received from authentication flow.")

                # Exchange code for token
                token = await self.token_client.get_token('authorization_code', code=code, code_verifier=code_verifier)
                
                # Restore original scope
                if scopes:
                    self.config.scope = original_scope
                    
                return token
        
        except (AuthenticationError, TokenError, ValidationError):
            raise
        except Exception as e:
            logger.error(f"Agent authentication failed: {e}")
            raise AuthenticationError(f"Agent authentication failed: {e}")

    async def get_organization_agent_token(
        self,
        switching_organization: str,
        agent_scopes: Optional[List[str]] = None,
        org_scopes: Optional[List[str]] = None
    ) -> OAuthToken:
        """Get access token for the AI agent and switch it to a sub-organization.

        :param switching_organization: The ID or UUID of the target organization.
        :param agent_scopes: Optional list of OAuth2 scopes to request for the initial agent token.
        :param org_scopes: Optional list of OAuth2 scopes to request for the switched token.
        :return: OAuth2 token for the switched organization.
        """
        if not switching_organization:
            raise ValidationError("switching_organization is required.")

        # 1. Get agent token.
        agent_token = await self.get_agent_token(scopes=agent_scopes)

        if not agent_token or not agent_token.access_token:
            raise TokenError("Failed to obtain a valid agent access token.")

        # 2. Switch token to organization.
        return await self.switch_token_to_organization(
            token=agent_token.access_token,
            switching_organization=switching_organization,
            scopes=org_scopes
        )

    def get_authorization_url(
        self,
        scopes: List[str],
        state: Optional[str] = None,
        resource: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[str, str]:
        """Generate authorization URL for user authentication.
        
        :param scopes: List of OAuth scopes to request
        :param state: Optional state parameter (generated if not provided)
        :param resource: Optional resource parameter
        :param kwargs: Additional parameters for the authorization URL
        :return: Tuple of (authorization_url, state)
        """
        if not state:
            state = generate_state()
            
        auth_params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "response_type": "code",
        }
        
        if resource:
            auth_params["resource"] = resource
            
        if self.agent_config:
            auth_params["requested_actor"] = self.agent_config.agent_id
            
        auth_params.update(kwargs)
        
        auth_url = build_authorization_url(
            f"{self.config.base_url}/oauth2/authorize",
            auth_params
        )
        return auth_url, state
    
    def get_authorization_url_with_pkce(
        self,
        scopes: List[str],
        state: Optional[str] = None,
        resource: Optional[str] = None,
        **kwargs: Any,
    ) -> Tuple[str, str, str]:
        """Generate authorization URL for user authentication.
        
        :param scopes: List of OAuth scopes to request
        :param state: Optional state parameter (generated if not provided)
        :param resource: Optional resource parameter
        :param kwargs: Additional parameters for the authorization URL
        :return: Tuple of (authorization_url, state)
        """
        if not state:
            state = generate_state()

        code_verifier, code_challenge = generate_pkce_pair()    
            
        auth_params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        
        if resource:
            auth_params["resource"] = resource
            
        if self.agent_config:
            auth_params["requested_actor"] = self.agent_config.agent_id
            
        auth_params.update(kwargs)
        
        auth_url = build_authorization_url(
            f"{self.config.base_url}/oauth2/authorize",
            auth_params
        )
        return auth_url, state, code_verifier    

    def _build_org_discovery_params(self, org_discovery_type: OrgDiscoveryType, discovery_value: str) -> dict:
        match org_discovery_type:
            case "orgID":
                return {"orgId": discovery_value}
            case "orgHandle":
                return {"orgHandle": discovery_value}
            case "org":
                return {"org": discovery_value}
            case "emailDomain":
                return {"login_hint": discovery_value, "orgDiscoveryType": "emailDomain"}
            case _:
                raise ValidationError(f"Unsupported org_discovery_type: {org_discovery_type}")

    def get_org_authorization_url(
        self,
        scopes: List[str],
        org_discovery_type: OrgDiscoveryType,
        discovery_value: str,
        state: Optional[str] = None,
        resource: Optional[str] = None,
        isEnhancedOrgAuth: Optional[bool] = False,
        **kwargs: Any,
    ) -> Tuple[str, str]:
        """Generate authorization URL for organization-specific user authentication.

        :param scopes: List of OAuth2 scopes to request
        :param org_discovery_type: The type of organization discovery ('orgID', 'orgHandle', 'org', 'emailDomain')
        :param discovery_value: The identifier whose meaning depends on ``org_discovery_type``:
            ``"orgID"`` → organization UUID, ``"orgHandle"`` → org handle slug,
            ``"org"`` → org name, ``"emailDomain"`` → user email address used as login hint.
        :param state: Optional state parameter (generated if not provided)
        :param resource: Optional resource parameter
        :param isEnhancedOrgAuth: If true, omits the fidp=OrganizationSSO parameter
        :param kwargs: Additional parameters for the authorization URL
        :return: Tuple of (authorization_url, state)
        """
        if not state:
            state = generate_state()

        auth_params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "response_type": "code",
        }

        if not isEnhancedOrgAuth:
            auth_params["fidp"] = "OrganizationSSO"

        auth_params.update(self._build_org_discovery_params(org_discovery_type, discovery_value))

        if resource:
            auth_params["resource"] = resource

        if self.agent_config:
            auth_params["requested_actor"] = self.agent_config.agent_id

        auth_params.update(kwargs)

        auth_url = build_authorization_url(
            f"{self.config.base_url}/oauth2/authorize",
            auth_params
        )
        return auth_url, state

    def get_org_authorization_url_with_pkce(
        self,
        scopes: List[str],
        org_discovery_type: OrgDiscoveryType,
        discovery_value: str,
        state: Optional[str] = None,
        resource: Optional[str] = None,
        isEnhancedOrgAuth: Optional[bool] = False,
        **kwargs: Any,
    ) -> Tuple[str, str, str]:
        """Generate authorization URL for organization-specific user authentication with PKCE.

        :param scopes: List of OAuth2 scopes to request
        :param org_discovery_type: The type of organization discovery ('orgID', 'orgHandle', 'org', 'emailDomain')
        :param discovery_value: The identifier whose meaning depends on ``org_discovery_type``:
            ``"orgID"`` → organization UUID, ``"orgHandle"`` → org handle slug,
            ``"org"`` → org name, ``"emailDomain"`` → user email address used as login hint.
        :param state: Optional state parameter (generated if not provided)
        :param resource: Optional resource parameter
        :param isEnhancedOrgAuth: If true, omits the fidp=OrganizationSSO parameter
        :param kwargs: Additional parameters for the authorization URL
        :return: Tuple of (authorization_url, state, code_verifier)
        """
        if not state:
            state = generate_state()

        code_verifier, code_challenge = generate_pkce_pair()

        auth_params = {
            "client_id": self.config.client_id,
            "redirect_uri": self.config.redirect_uri,
            "scope": " ".join(scopes),
            "state": state,
            "response_type": "code",
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        if not isEnhancedOrgAuth:
            auth_params["fidp"] = "OrganizationSSO"

        auth_params.update(self._build_org_discovery_params(org_discovery_type, discovery_value))

        if resource:
            auth_params["resource"] = resource

        if self.agent_config:
            auth_params["requested_actor"] = self.agent_config.agent_id

        auth_params.update(kwargs)

        auth_url = build_authorization_url(
            f"{self.config.base_url}/oauth2/authorize",
            auth_params
        )
        return auth_url, state, code_verifier

    async def get_obo_token(
        self,
        auth_code: str,
        agent_token: str,
        scopes: Optional[List[str]] = None,
        code_verifier: Optional[str] = None
    ) -> OAuthToken:
        """Get on-behalf-of (OBO) token for user using authorization code.
        
        :param auth_code: Authorization code from user authentication
        :param scopes: Optional list of scopes to request
        :param agent_token: Optional agent token for delegation
        :return: OAuth token for the user
        """
        if not auth_code:
            raise ValidationError("Authorization code is required for OBO token exchange.")
        
        try:
            actor_token_val = agent_token.access_token if agent_token else None
            scope_str = ' '.join(scopes) if scopes else None
            
            token = await self.token_client.get_token(
                'authorization_code',
                code=auth_code,
                scope=scope_str,
                actor_token=actor_token_val,
                code_verifier=code_verifier
            )
            return token
            
        except (TokenError, ValidationError):
            raise
        except Exception as e:
            logger.error(f"OBO token exchange failed: {e}")
            raise TokenError(f"OBO token exchange failed: {e}")

    async def _poll_for_token(
        self,
        ciba_response: CIBAResponse,
        scope: Optional[str] = None,
        timeout: Optional[int] = None,
    ) -> OAuthToken:
        """Poll the token endpoint until CIBA authentication completes.

        :param ciba_response: CIBA initiation response with auth_req_id, interval, expires_in
        :param scope: Optional scope override
        :param timeout: Optional max wait time in seconds (defaults to ciba_response.expires_in)
        :return: OAuthToken on successful authentication
        :raises CIBAAuthenticationError: If authentication is denied or expires
        """
        interval = ciba_response.interval
        max_wait = min(
            timeout or ciba_response.expires_in,
            ciba_response.expires_in,
        )
        start_time = time.monotonic()

        while True:
            elapsed = time.monotonic() - start_time
            if elapsed >= max_wait:
                raise CIBAAuthenticationError(
                    "CIBA authentication timed out: exceeded maximum wait time."
                )

            await asyncio.sleep(interval)

            try:
                token = await self.token_client.get_token(
                    "urn:openid:params:grant-type:ciba",
                    auth_req_id=ciba_response.auth_req_id,
                    scope=scope,
                )
                return token
            except CIBAAuthenticationError as e:
                error_msg = str(e)
                if CIBAStatus.AUTHORIZATION_PENDING in error_msg:
                    logger.debug("CIBA authorization pending, continuing to poll...")
                    continue
                elif CIBAStatus.SLOW_DOWN in error_msg:
                    interval += 5
                    logger.debug(f"CIBA slow_down received, increasing interval to {interval}s")
                    continue
                elif CIBAStatus.EXPIRED_TOKEN in error_msg:
                    raise CIBAAuthenticationError(
                        "CIBA authentication request expired. The user did not authenticate in time."
                    )
                elif CIBAStatus.ACCESS_DENIED in error_msg:
                    raise CIBAAuthenticationError(
                        "CIBA authentication denied. The user rejected the authentication request."
                    )
                else:
                    raise

    async def get_obo_token_with_ciba(
        self,
        login_hint: str,
        agent_token: OAuthToken,
        scopes: Optional[List[str]] = None,
        binding_message: Optional[str] = None,
        notification_channel: Optional[str] = None,
        timeout: Optional[int] = None,
        on_initiated: Optional[Callable[[CIBAResponse], None]] = None,
    ) -> Tuple[CIBAResponse, OAuthToken]:
        """Get on-behalf-of token using CIBA flow.

        Initiates a CIBA request for a user identified by login_hint,
        then polls until the user authenticates. The actor_token is sent
        in the CIBA initiation to establish OBO delegation.

        :param login_hint: Username or identifier of the user to authenticate
        :param agent_token: The agent's OAuthToken (used as actor_token for delegation)
        :param scopes: List of OAuth2 scopes to request
        :param binding_message: Message displayed to the user during authentication
        :param notification_channel: Notification channel (email, sms, external)
        :param timeout: Maximum time to wait for authentication in seconds
        :param on_initiated: Optional callback invoked with CIBAResponse immediately after
            the CIBA request is accepted and before polling begins. Use this to notify the
            caller that a push/email/SMS has been sent and polling is starting.
            Accepts both sync and async callables.
        :return: Tuple of (CIBAResponse, OAuthToken)
        """
        if not login_hint:
            raise ValidationError("login_hint is required for CIBA OBO token exchange.")
        if not agent_token:
            raise ValidationError("agent_token is required for CIBA OBO token exchange.")

        scope_str = " ".join(scopes) if scopes else None

        try:
            ciba_response = await self.token_client.initiate_ciba(
                login_hint=login_hint,
                scope=scope_str,
                binding_message=binding_message,
                notification_channel=notification_channel,
                actor_token=agent_token.access_token,
            )

            logger.info(
                f"CIBA initiated for user '{login_hint}'. auth_req_id: {ciba_response.auth_req_id}, "
                f"expires_in: {ciba_response.expires_in}s"
            )

            if on_initiated is not None:
                result = on_initiated(ciba_response)
                if asyncio.iscoroutine(result):
                    await result

            token = await self._poll_for_token(
                ciba_response=ciba_response,
                scope=scope_str,
                timeout=timeout,
            )
            return ciba_response, token

        except (CIBAAuthenticationError, ValidationError):
            raise
        except Exception as e:
            logger.error(f"CIBA OBO token exchange failed: {e}", exc_info=True)
            raise TokenError(f"CIBA OBO token exchange failed: {e}") from e

    async def switch_token_to_organization(
        self,
        token: str,
        switching_organization: str,
        scopes: Optional[List[str]] = None
    ) -> OAuthToken:
        """Switch token to a sub-organization.

        :param token: The current access token to be switched.
        :param switching_organization: The ID or UUID of the target organization.
        :param scopes: Optional list of scopes to request.
        :return: OAuth2 token for the switched organization.
        """
        if not token:
            raise ValidationError("Token is required for organization switch.")
        if not switching_organization:
            raise ValidationError("switching_organization is required.")

        scope_str = ' '.join(scopes) if scopes else None

        try:
            switched_token = await self.token_client.get_token(
                'organization_switch',
                token=token,
                switching_organization=switching_organization,
                scope=scope_str
            )
            return switched_token

        except (TokenError, ValidationError):
            raise
        except Exception as e:
            logger.error(f"Organization switch failed: {e}", exc_info=True)
            raise TokenError(f"Organization switch failed: {e}") from e

    async def revoke_token(
        self, 
        token: str, 
        token_type_hint: str = "access_token"
    ) -> bool:
        """Revoke an access or refresh token.
        
        :param token: Token to revoke
        :param token_type_hint: Type of token being revoked
        :return: True if revocation succeeded, False otherwise
        """
        try:
            return await self.token_client.revoke_token(token, token_type_hint)
        except Exception as e:
            logger.error(f"Token revocation failed: {e}")
            return False

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
        return False

    # Backwards compatibility
    async def close(self):
        """Close the agent auth manager and cleanup resources."""
        await self.token_client.close()

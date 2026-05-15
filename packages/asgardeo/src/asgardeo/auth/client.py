
"""
Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com).
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

"""Async Asgardeo authentication and token clients."""

import base64
import json
import logging
from typing import Any
from urllib.parse import urlencode

import httpx

from ..models import (
    AsgardeoConfig,
    AsgardeoError,
    AuthenticationError,
    CIBAAuthenticationError,
    CIBAResponse,
    CIBAStatus,
    FlowStatus,
    NetworkError,
    OAuthToken,
    TokenError,
    ValidationError,
)

logger = logging.getLogger(__name__)

class AsgardeoNativeAuthClient:
    """Async client for handling Asgardeo App Native Authentication flows.

    This client manages the authentication process without browser redirects and keeps track of the flow status.
    It also creates an internal TokenClient for token operations.
    """

    def __init__(self, config: AsgardeoConfig) -> None:
        """Initialize the Auth Client.

        :param config: AsgardeoConfig instance with configuration
        """
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        self.session = httpx.AsyncClient()
        self.flow_id: str | None = None
        self.flow_status: str | None = None
        self.next_step: dict[str, Any] | None = None
        self.auth_data: dict[str, Any] | None = None
        self.token_client = AsgardeoTokenClient(config)

    async def _initiate_auth(
        self,
        state: str | None = None,
        params: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Private method to initiate the authentication flow.

        :param state: Optional state parameter
        :return: Dictionary response from the initiation request
        """
        url = f"{self.base_url}/oauth2/authorize"
        data = {
            "client_id": self.config.client_id,
            "response_type": "code",
            "redirect_uri": self.config.redirect_uri,
            "scope": self.config.scope,
            "response_mode": "direct",
        }

        # Always authenticate confidential clients even when using PKCE.
        # PKCE prevents auth code interception; client_secret authenticates the client.
        # Public clients (no client_secret) rely on PKCE alone.
        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret
        if state:
            data["state"] = state
        if params:
            data.update(params)

        try:
            response = await self.session.post(
                url,
                headers=self.headers,
                data=urlencode(data),
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise AuthenticationError(
                f"Authentication initiation failed: {e.response.status_code} {e.response.text}",
            )
        except httpx.RequestError as e:
            raise NetworkError(
                f"Network error during authentication initiation: {e!s}",
            )
        except Exception as e:
            raise AsgardeoError(
                f"Unexpected error during authentication initiation: {e!s}",
            )

    async def _perform_auth_step(
        self,
        flow_id: str,
        authenticator_id: str | None = None,
        params: dict[str, Any] | None = None,
        scenario: str | None = None,
    ) -> dict[str, Any]:
        """Private method to perform an authentication step.

        :param flow_id: Flow ID for the authentication step
        :param authenticator_id: Authenticator ID to use
        :param params: Dictionary of parameters for the authenticator
        :param scenario: Optional scenario
        :return: Dictionary response from the authentication step
        """
        url = f"{self.base_url}/oauth2/authn"
        body = {
            "flowId": flow_id,
        }
        if authenticator_id:
            body["selectedAuthenticator"] = {"authenticatorId": authenticator_id}
            if params:
                body["selectedAuthenticator"]["params"] = params
        if scenario:
            body["scenario"] = scenario

        headers = {"Content-Type": "application/json"}
        try:
            response = await self.session.post(
                url,
                headers=headers,
                data=json.dumps(body),
            )
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            raise AuthenticationError(
                f"Authentication step failed: {e.response.status_code} {e.response.text}",
            )
        except httpx.RequestError as e:
            raise NetworkError(f"Network error during authentication step: {e!s}")
        except Exception as e:
            raise AsgardeoError(
                f"Unexpected error during authentication step: {e!s}",
            )

    async def authenticate(
        self,
        flow_id: str | None = None,
        authenticator_id: str | None = None,
        params: dict[str, Any] | None = None,
        scenario: str | None = None,
        state: str | None = None,
    ) -> dict[str, Any]:
        """Unified authentication function. If flow_id is not provided, uses the internal flow_id if available.

        If no flow_id exists, initiates the authentication flow.
        Updates the internal flow status after each call.

        :param flow_id: Flow ID from previous step (optional, uses internal if not provided)
        :param authenticator_id: Authenticator ID to use (required for steps after initiation)
        :param params: Dictionary of parameters for the authenticator (e.g., {'username': 'user', 'password': 'pass'})
        :param scenario: Optional scenario, e.g., 'PROCEED_PUSH_AUTHENTICATION' for push notifications
        :param state: Optional state parameter (for initiation)
        :return: Dictionary response with flowId, flowStatus, nextStep, etc. (or authData if completed)
        """
        if flow_id is None and self.flow_id is None:
            # Initiation
            resp_json = await self._initiate_auth(state, params)
        else:
            # Authentication step
            effective_flow_id = flow_id or self.flow_id
            if effective_flow_id is None:
                raise ValidationError("Flow ID is required for authentication steps.")
            resp_json = await self._perform_auth_step(
                effective_flow_id,
                authenticator_id,
                params,
                scenario,
            )

        # Update internal state
        self.flow_id = resp_json.get("flowId", self.flow_id)
        self.flow_status = resp_json.get("flowStatus")
        self.next_step = resp_json.get("nextStep")
        if self.flow_status == FlowStatus.SUCCESS_COMPLETED:
            self.auth_data = resp_json.get("authData")

        return resp_json

    async def get_token(self) -> OAuthToken:
        """Convenience method to exchange the authorization code for tokens after successful authentication.

        Uses the authorization code grant type.

        :return: OAuthToken instance with access_token, id_token, etc.
        """
        if not self.auth_data or "code" not in self.auth_data:
            raise TokenError(
                "Authentication not completed or no authorization code available.",
            )
        return await self.token_client.get_token(
            "authorization_code",
            code=self.auth_data["code"],
        )

    def reset_flow(self) -> None:
        """Reset the internal flow state."""
        self.flow_id = None
        self.flow_status = None
        self.next_step = None
        self.auth_data = None

    async def __aenter__(self):
        """Async context manager entry."""
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.close()
        return False
    
    async def close(self):
        """Close the auth client and cleanup resources."""
        await self.session.aclose()
        await self.token_client.close()

    async def authenticate_with_password(
        self, username: str, password: str
    ) -> OAuthToken:
        """Complete authentication flow with username/password in one call.

        :param username: Username for authentication
        :param password: Password for authentication
        :return: OAuthToken instance with tokens
        """
        # Start authentication flow
        await self.authenticate()

        # Complete with credentials
        await self.authenticate(
            authenticator_id="BasicAuthenticator",
            params={"username": username, "password": password},
        )

        # Get tokens
        return await self.get_tokens()


class AsgardeoTokenClient:
    """Async client for handling token operations in Asgardeo.

    This client manages token exchange and refresh.
    """

    def __init__(self, config: AsgardeoConfig) -> None:
        """Initialize the Token Client.

        :param config: AsgardeoConfig instance with configuration
        """
        self.config = config
        self.base_url = config.base_url.rstrip("/")
        self.headers = {"Content-Type": "application/x-www-form-urlencoded"}
        self.session = httpx.AsyncClient()

    async def get_token(self, grant_type: str, **kwargs: Any) -> OAuthToken:
        """Unified token request function for various grant types.

        :param grant_type: The grant type (e.g., 'authorization_code', 'refresh_token')
        :param kwargs: Additional parameters based on grant type:
            - For 'authorization_code': code (required), redirect_uri (optional, uses config.redirect_uri if not provided)
            - For 'refresh_token': refresh_token (required), scope (optional)
        :return: OAuthToken instance with access_token, id_token, etc.
        """
        url = f"{self.base_url}/oauth2/token"
        data = {"grant_type": grant_type, "client_id": self.config.client_id}

        if self.config.client_secret:
            data["client_secret"] = self.config.client_secret

        if grant_type == "authorization_code":
            code = kwargs.get("code")
            if not code:
                raise ValidationError(
                    "Authorization code is required for 'authorization_code' grant type.",
                )
            data["code"] = code
            data["redirect_uri"] = kwargs.get("redirect_uri", self.config.redirect_uri)
            if "code_verifier" in kwargs:
                data["code_verifier"] = kwargs.get("code_verifier")            
            if "actor_token" in kwargs:
                data["actor_token"] = kwargs.get("actor_token")
        elif grant_type == "refresh_token":
            refresh_token = kwargs.get("refresh_token")
            if not refresh_token:
                raise ValidationError(
                    "Refresh token is required for 'refresh_token' grant type.",
                )
            data["refresh_token"] = refresh_token
            scope = kwargs.get("scope")
            if scope:
                data["scope"] = scope
        elif grant_type == "urn:openid:params:grant-type:ciba":
            auth_req_id = kwargs.get("auth_req_id")
            if not auth_req_id:
                raise ValidationError(
                    "auth_req_id is required for CIBA grant type.",
                )
            data["auth_req_id"] = auth_req_id
            scope = kwargs.get("scope")
            if scope:
                data["scope"] = scope
        elif grant_type == "organization_switch":
            token = kwargs.get("token")
            switching_organization = kwargs.get("switching_organization")
            if not token or not switching_organization:
                raise ValidationError(
                    "token and switching_organization are required for 'organization_switch' grant type.",
                )
            data["token"] = token
            data["switching_organization"] = switching_organization
            scope = kwargs.get("scope")
            if scope:
                data["scope"] = scope
        else:
            raise ValidationError(f"Unsupported grant type: {grant_type}")

        try:
            response = await self.session.post(
                url,
                headers=self.headers,
                data=urlencode(data),
            )
            response.raise_for_status()
            resp_json = response.json()
            return OAuthToken(
                access_token=resp_json["access_token"],
                id_token=resp_json.get("id_token"),
                refresh_token=resp_json.get("refresh_token"),
                expires_in=resp_json.get("expires_in"),
                scope=resp_json.get("scope"),
            )
        except httpx.HTTPStatusError as e:
            if grant_type == "urn:openid:params:grant-type:ciba" and e.response.status_code == 400:
                try:
                    error_json = e.response.json()
                    error_code = error_json.get("error", "")
                    if error_code in (
                        CIBAStatus.AUTHORIZATION_PENDING,
                        CIBAStatus.SLOW_DOWN,
                        CIBAStatus.EXPIRED_TOKEN,
                        CIBAStatus.ACCESS_DENIED,
                    ):
                        raise CIBAAuthenticationError(error_code)
                except (ValueError, KeyError):
                    pass
            raise TokenError(
                f"Token request failed: {e.response.status_code} {e.response.text}",
            )
        except httpx.RequestError as e:
            raise NetworkError(f"Network error during token request: {e!s}")
        except KeyError as e:
            raise TokenError(f"Missing required field in token response: {e!s}")
        except Exception as e:
            raise AsgardeoError(f"Unexpected error during token request: {e!s}")

    def _get_basic_auth_header(self) -> str:
        """Generate Basic auth header value from client credentials.

        :return: Basic auth header value string
        :raises ValidationError: If client_secret is not configured
        """
        if not self.config.client_secret:
            raise ValidationError("Client secret is required for Basic authentication.")
        credentials = f"{self.config.client_id}:{self.config.client_secret}"
        encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
        return f"Basic {encoded}"

    async def initiate_ciba(
        self,
        login_hint: str,
        scope: str | None = None,
        binding_message: str | None = None,
        notification_channel: str | None = None,
        actor_token: str | None = None,
    ) -> CIBAResponse:
        """Initiate a CIBA backchannel authentication request.

        :param login_hint: Username or identifier of the user to authenticate
        :param scope: Space-separated scopes to request (defaults to config scope)
        :param binding_message: Human-readable message displayed during authentication
        :param notification_channel: Notification channel (email, sms, external)
        :param actor_token: Optional actor token for OBO delegation
        :return: CIBAResponse with auth_req_id, interval, expires_in, optional auth_url
        """
        url = f"{self.base_url}/oauth2/ciba"

        headers = {"Content-Type": "application/x-www-form-urlencoded"}

        data = {
            "scope": scope or self.config.scope,
            "login_hint": login_hint,
        }

        if self.config.client_secret:
            headers["Authorization"] = self._get_basic_auth_header()
        else:
            data["client_id"] = self.config.client_id

        if binding_message:
            data["binding_message"] = binding_message

        if notification_channel:
            data["notification_channel"] = notification_channel

        if actor_token:
            data["actor_token"] = actor_token

        try:
            response = await self.session.post(
                url,
                headers=headers,
                data=urlencode(data),
            )
            response.raise_for_status()
            resp_json = response.json()
            return CIBAResponse(
                auth_req_id=resp_json["auth_req_id"],
                interval=resp_json.get("interval", 2),
                expires_in=resp_json.get("expires_in", 120),
                auth_url=resp_json.get("auth_url"),
            )
        except httpx.HTTPStatusError as e:
            raise AuthenticationError(
                f"CIBA initiation failed: {e.response.status_code} {e.response.text}",
            )
        except httpx.RequestError as e:
            raise NetworkError(f"Network error during CIBA initiation: {e!s}")
        except KeyError as e:
            raise AuthenticationError(f"Missing required field in CIBA response: {e!s}")
        except Exception as e:
            raise AsgardeoError(f"Unexpected error during CIBA initiation: {e!s}")

    async def refresh_access_token(self, refresh_token: str) -> OAuthToken:
        """Simple token refresh method.

        :param refresh_token: Refresh token to use
        :return: New OAuthToken instance
        """
        return await self.get_token("refresh_token", refresh_token=refresh_token)
    
    async def __aenter__(self):
        """Async context manager entry."""
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        await self.session.aclose()
        return False
    
    async def close(self):
        """Close the token client and cleanup resources."""
        await self.session.aclose()

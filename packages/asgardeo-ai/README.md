# Asgardeo AI SDK

> ⚠️ WARNING: Asgardeo AI SDK is currently under development, is not intended for production use, and therefore has no official support.

Python SDK for Asgardeo AI agent authentication and on-behalf-of (OBO) token flows.

## Features

- **Agent Authentication**: Authenticate AI agents using native auth (username/password + PKCE).
- **Organization Token Switching**: Switch tokens into child organization contexts.
- **On-Behalf-Of (OBO) Tokens**: Get user tokens delegated to the agent via auth-code or CIBA.
- **CIBA Push Authentication**: Push auth requests to users' devices and poll until approved.
- **Async/Await Support**: Full async implementation using httpx.
- **Token Management**: Handle token exchange, refresh, and revocation.
- **Authorization URLs**: Generate standard, PKCE, and organization authorization URLs.

## Installation

Install from local development:

```bash
pip install -e .
```

## Quick Start

### Basic Setup

```python
import asyncio
from asgardeo import AsgardeoConfig
from asgardeo_ai import AgentAuthManager, AgentConfig

# Configure Asgardeo connection
config = AsgardeoConfig(
    base_url="https://api.asgardeo.io/t/your-organization",
    client_id="your_client_id", 
    redirect_uri="https://your-app.com/callback",
    client_secret="your_client_secret"
)

# Configure AI agent
agent_config = AgentConfig(
    agent_id="your_agent_id",
    agent_secret="your_agent_secret"
)

# Create auth manager
auth_manager = AgentAuthManager(config, agent_config)
```

### Agent Authentication

```python
async def main():
    async with AgentAuthManager(config, agent_config) as auth_manager:
        # Get token for the AI agent
        agent_token = await auth_manager.get_agent_token(["openid", "profile"])
        print(f"Agent access token: {agent_token.access_token}")

asyncio.run(main())
```

### User Authorization Flow

```python
async def user_auth_flow():
    async with AgentAuthManager(config, agent_config) as auth_manager:
        # Generate authorization URL for user
        scopes = ["openid", "profile", "email"]
        auth_url, state = auth_manager.get_authorization_url(scopes)
        
        print(f"Redirect user to: {auth_url}")

        # After user authorizes and you receive the auth code:
        auth_code = "received_from_callback"
        agent_token = await auth_manager.get_agent_token(["openid"])

        # Get OBO token for the user
        obo_token = await auth_manager.get_obo_token(auth_code, scopes, agent_token)
        print(f"User access token: {obo_token.access_token}")
```

### Child Organization User Authorization Flow

```python
async def child_org_user_auth_flow():
    async with AgentAuthManager(config, agent_config) as auth_manager:
        # 1. Get an agent token for the child organization
        org_agent_token = await auth_manager.get_organization_agent_token(
            switching_organization="org-uuid-here",
            org_scopes=["openid", "internal_org_user_mgt_view"],
        )

        # 2. Build an authorization URL scoped to the child organization
        scopes = ["openid", "profile", "email"]
        auth_url, state = auth_manager.get_org_authorization_url(
            scopes=scopes,
            org_discovery_type="orgID",
            discovery_value="org-uuid-here",
        )
        print(f"Redirect user to: {auth_url}")

        # 3. After user authorizes, receive the auth code from the callback
        auth_code = "received_from_callback"

        # 4. Exchange the auth code for an OBO token delegated to the agent
        obo_token = await auth_manager.get_obo_token(auth_code, scopes, org_agent_token)
        print(f"Org-scoped user access token: {obo_token.access_token}")
```

### Organization Agent Authentication

```python
async def org_agent_flow():
    async with AgentAuthManager(config, agent_config) as auth_manager:
        # Authenticate as agent and switch into a child organization in one call.
        org_token = await auth_manager.get_organization_agent_token(
            switching_organization="org-uuid-here",
            org_scopes=["openid", "internal_org_user_mgt_view"],
        )
        print(f"Organization token: {org_token.access_token}")
```

### Switch Agent Token to Organization

```python
async def switch_token_flow():
    async with AgentAuthManager(config, agent_config) as auth_manager:
        # Switch any existing root access token into a child organization context.
        org_token = await auth_manager.switch_token_to_organization(
            token="existing_access_token",
            switching_organization="org-uuid-here",
            scopes=["openid", "internal_org_user_mgt_view"],
        )
        print(f"Organization token: {org_token.access_token}")
```

## API Reference

### AgentAuthManager

Main class for handling agent authentication and OBO flows.

#### Constructor

```python
AgentAuthManager(
    config: AsgardeoConfig,
    agent_config: Optional[AgentConfig] = None,
    authorization_timeout: int = 300,
)
```

#### Methods

| Method | Description | Returns |
|--------|-------------|---------|
| `get_agent_token(scopes)` | Authenticates the agent via native auth (username/password + PKCE) | `OAuthToken` |
| `get_organization_agent_token(switching_organization, agent_scopes, org_scopes)` | Gets agent token then switches it to a child-org in one call | `OAuthToken` |
| `get_authorization_url(scopes, state, resource, **kwargs)` | Builds an OAuth2 authorization URL to redirect a user to | `Tuple[str, str]` — `(url, state)` |
| `get_authorization_url_with_pkce(scopes, state, resource, **kwargs)` | Same as above but generates and returns a PKCE `code_verifier` | `Tuple[str, str, str]` — `(url, state, code_verifier)` |
| `get_org_authorization_url(scopes, org_discovery_type, discovery_value, ...)` | Authorization URL with org-discovery params (`orgID`, `orgHandle`, `org`, `emailDomain`) | `Tuple[str, str]` — `(url, state)` |
| `get_org_authorization_url_with_pkce(scopes, org_discovery_type, discovery_value, ...)` | Org authorization URL with PKCE | `Tuple[str, str, str]` — `(url, state, code_verifier)` |
| `get_obo_token(auth_code, agent_token, scopes, code_verifier)` | Exchanges a user's auth code for an OBO token delegated to the agent | `OAuthToken` |
| `get_obo_token_with_ciba(login_hint, agent_token, scopes, ...)` | Push-based OBO — sends auth request to user's device and polls until approved | `Tuple[CIBAResponse, OAuthToken]` |
| `switch_token_to_organization(token, switching_organization, scopes)` | Switches any access token into a child-org scoped token | `OAuthToken` |
| `revoke_token(token, token_type_hint)` | Revokes an access or refresh token | `bool` |

#### `get_org_authorization_url` / `get_org_authorization_url_with_pkce` — `org_discovery_type` values

| Value | `discovery_value` meaning |
|-------|--------------------------|
| `"orgID"` | Organization UUID |
| `"orgHandle"` | Organization handle/slug |
| `"org"` | Organization name |
| `"emailDomain"` | User email address (used as `login_hint` with domain-based discovery) |

### AgentConfig

Configuration for AI agent credentials.

- `agent_id: str`: Agent identifier
- `agent_secret: str`: Agent secret

## Requirements
- Python >= 3.10
- `httpx` (for async HTTP)
- `asgardeo` (base SDK)

## Development

```bash
# Install dependencies
poetry install

# Build
poetry build
```

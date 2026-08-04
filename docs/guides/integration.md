# Integration

<!-- TOC START -->
- [Overview](#overview)
- [FLEXT-Core Integration](#flext-core-integration)
  - [Authentication-Specific Integration](#authentication-specific-integration)
  - [FlextContainer Integration](#flextcontainer-integration)
  - [Domain Modeling](#domain-modeling)
- [Integration with FLEXT Projects](#integration-with-flext-projects)
  - [flext-api Integration](#flext-api-integration)
  - [flext-web Integration](#flext-web-integration)
  - [flext-cli Integration](#flext-cli-integration)
- [Service Integration Patterns](#service-integration-patterns)
  - [Authentication Service Provider](#authentication-service-provider)
  - [Inter-Service Authentication](#inter-service-authentication)
- [Database Integration](#database-integration)
  - [User Storage (Future)](#user-storage-future)
  - [Session Storage (Future)](#session-storage-future)
- [Configuration Integration](#configuration-integration)
  - [Environment-Aware Configuration](#environment-aware-configuration)
  - [Shared Configuration](#shared-configuration)
- [Testing Integration](#testing-integration)
  - [Integration Testing](#integration-testing)
- [Future Integration Plans](#future-integration-plans)
  - [Modern Authentication Protocols](#modern-authentication-protocols)
  - [Enterprise SSO](#enterprise-sso)
<!-- TOC END -->

**Version**: 0.12.0-dev | **Updated**: April 14, 2026

Integration patterns for flext-auth within the FLEXT ecosystem.

______________________________________________________________________

## Overview

flext-auth integrates with the FLEXT ecosystem through
[flext-core](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/README.md)
foundation patterns and provides authentication services to other FLEXT projects.

**Integration Status**: 85% flext-core pattern compliance

______________________________________________________________________

## FLEXT-Core Integration

flext-auth follows
**[flext-core](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/README.md)**
patterns. For complete `r` usage patterns, see the flext-core documentation.

### Authentication-Specific Integration

Authentication operations return `r` for consistency with the FLEXT ecosystem:

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)

# Basic authentication pattern
auth_result = auth.authenticate_user("username", "password")
if auth_result.success:
    identity = auth_result.unwrap()
    u.Cli.info(f"Authentication successful: {identity.name}")
else:
    u.Cli.info(f"Authentication failed: {auth_result.error}")```
### FlextContainer Integration

Use `FlextContainer` for dependency injection:

```python
from __future__ import annotations
from flext_cli import u
from flext_core import FlextContainer, FlextSettings
from flext_auth import FlextAuth, FlextAuthSettings

# Register authentication service
container = FlextContainer()

settings = FlextAuthSettings()
auth_service = FlextAuth(settings=settings)
container.bind("auth_service", auth_service)


# Use from container in other services
class UserService:
    def __init__(self):
        self._container = FlextContainer()
        self._auth = self._container.resolve("auth_service").unwrap()

    def create_authenticated_user(self, user_data: dict):
        # Use injected auth service
        return self._auth.register_user(**user_data)
```

### Domain Modeling

All domain entities use `FlextModels` patterns:

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)

# Create an identity via the service (preferred over direct model creation)
result = auth.register_user("demo", "demo@example.com", "secure123")
if result.success:
    identity = result.unwrap()
    u.Cli.info(f"Identity created: {identity.name}")```
______________________________________________________________________

## Integration with FLEXT Projects

### flext-api Integration

Authentication middleware for REST APIs:

```python
from __future__ import annotations
from flext_auth import FlextAuth
from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPBearer

app = FastAPI()
auth = FlextAuth.quick_start(create_admin_user=False)
security = HTTPBearer()


def authenticate_request(token: str = Depends(security)):
    """Authentication middleware for FastAPI."""
    # Validate token using the underlying token service
    token_result = auth.create_token("identity-id")
    if token_result.failure:
        raise HTTPException(status_code=401, detail=token_result.error)

    return token_result.unwrap()


@app.get("/protected")
def protected_endpoint(token: str = Depends(authenticate_request)):
    return {"message": "Hello authenticated user"}```
### flext-web Integration

Web application authentication flows:

```python
from __future__ import annotations
from flask import Flask, flash, redirect, request, session, url_for
from flext_auth import FlextAuth

app = Flask(__name__)
auth = FlextAuth.quick_start(create_admin_user=False)


@app.route("/login", methods=["POST"])
def login():
    username = request.form["username"]
    password = request.form["password"]

    auth_result = auth.authenticate_user(username, password)

    if auth_result.success:
        identity = auth_result.unwrap()
        session["token"] = identity.token
        session["user"] = identity.name
        return redirect(url_for("dashboard"))
    flash(f"Login failed: {auth_result.error}")
    return redirect(url_for("login_page"))


def require_auth(f):
    """Authentication decorator for Flask routes."""

    def decorated_function(*args, **kwargs):
        token = session.get("token")
        if not token:
            return redirect(url_for("login_page"))

        # In production, validate token against the token service
        return f(*args, **kwargs)

    return decorated_function```
### flext-cli Integration

CLI authentication patterns:

```python
from __future__ import annotations

import click
from flext_auth import FlextAuth


@click.group()
@click.pass_context
def cli(ctx):
    """CLI with authentication support."""
    ctx.ensure_object(dict)
    ctx.obj["auth"] = FlextAuth.quick_start(create_admin_user=False)


@cli.command()
@click.option("--username", prompt=True)
@click.option("--password", prompt=True, hide_input=True)
@click.pass_context
def login(ctx, username, password):
    """Authenticate user for CLI operations."""
    auth = ctx.obj["auth"]
    result = auth.authenticate_user(username, password)

    if result.success:
        identity = result.unwrap()
        ctx.obj["token"] = identity.token
        click.echo("Authentication successful")
    else:
        click.echo(f"Authentication failed: {result.error}")
        ctx.exit(1)```
______________________________________________________________________

## Service Integration Patterns

### Authentication Service Provider

flext-auth acts as an authentication service provider for the ecosystem:

```python
from __future__ import annotations
from flext_auth import FlextAuth
from flext_core import FlextContainer, m, p


class AuthenticationProvider:
    """Centralized authentication for the FLEXT ecosystem."""

    def __init__(self):
        self._auth = FlextAuth.quick_start(create_admin_user=False)
        self._container = FlextContainer()

    def authenticate_service_request(self, token: str) -> p.Result[m.Auth.AuthIdentity]:
        """Authenticate requests from other FLEXT services."""
        # Decode token via the token service to resolve the identity id
        return self._auth.token_service.decode_token(token)

    def create_service_token(self, identity_id: str) -> p.Result[str]:
        """Create a token for service-to-service authentication."""
        return self._auth.create_token(identity_id)```
### Inter-Service Authentication

Pattern for service-to-service authentication:

```python
from __future__ import annotations
from flext_auth import FlextAuth
from flext_api import FlextApi
from flext_core import m, p


# Service A calling Service B
class ServiceA:
    def __init__(self):
        self._auth = FlextAuth.quick_start(create_admin_user=False)
        self._api = FlextApi()

    def _get_service_token(self) -> str:
        result = self._auth.create_token("service-a")
        return result.unwrap() if result.success else ""

    def call_service_b(self, data: dict) -> p.Result[m.Dict]:
        """Call Service B with authentication."""
        headers = {
            "Authorization": f"Bearer {self._get_service_token()}",
            "Content-Type": "application/json",
        }

        # Make authenticated request to Service B using flext-api
        result = self._api.post(
            url="http://service-b/api/endpoint", json=data, headers=headers
        )
        return result```
______________________________________________________________________

## Database Integration

### User Storage (Future)

Integration with flext-db-oracle for user storage:

```python
from __future__ import annotations
from flext_auth import m as auth_m
from flext_core import p


class UserRepository:
    """User storage using Oracle database."""

    def find_by_username(self, username: str) -> p.Result[auth_m.Auth.AuthIdentity]:
        """Find user by username."""
        # Oracle-specific implementation
        ...

    def create_user(
        self, user: auth_m.Auth.AuthIdentity
    ) -> p.Result[auth_m.Auth.AuthIdentity]:
        """Create user in database."""
        # Oracle-specific implementation
        ...```
### Session Storage (Future)

Integration with Redis for session management:

```python
from __future__ import annotations
from flext_auth import m as auth_m
from flext_core import p, r


class RedisSessionStorage:
    """Session storage using Redis."""

    def __init__(self, redis_client) -> None:
        self._redis = redis_client

    def store_session(self, session: auth_m.Auth.Session) -> p.Result[bool]:
        """Store session in Redis."""
        try:
            session_data = session.model_dump_json()
            self._redis.setex(
                session.session_token, int(session.expires_at.timestamp()), session_data
            )
            return r[bool].ok(True)
        except Exception as e:
            return r[bool].fail(f"Session storage failed: {e}")```
______________________________________________________________________

## Configuration Integration

### Environment-Aware Configuration

Integration with FLEXT environment management:

```python
import os
from flext_auth import FlextAuth, FlextAuthSettings
from flext_cli import u

# Environment detection
flext_env = os.getenv("FLEXT_ENV", "development")

# Create environment-specific configuration
auth_config = FlextAuthSettings()
auth = FlextAuth(settings=auth_config)
u.Cli.info(f"Environment: {flext_env}")```
### Shared Configuration

Integration with FLEXT workspace configuration:

```python
from __future__ import annotations
from flext_auth import FlextAuth, FlextAuthSettings
from flext_core import FlextSettings, p, r


class FlextAuthWorkspaceSettings(FlextSettings):
    """Authentication configuration within the FLEXT workspace."""

    auth_config: FlextAuthSettings

    def get_auth_service(self) -> p.Result[FlextAuth]:
        """Get configured authentication service."""
        return r[FlextAuth].ok(FlextAuth(settings=self.auth_config))```
______________________________________________________________________

## Testing Integration

### Integration Testing

Test authentication with other FLEXT services:

```python
from __future__ import annotations

from flext_auth import FlextAuth


class TestAuthIntegration:
    def test_auth_with_api_service(self):
        """Test authentication integration with API service."""
        # Arrange
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Act
        result = auth.register_user("test", "test@example.com", "password123")
        assert result.success

        auth_result = auth.authenticate_user("test", "password123")
        assert auth_result.success

        identity = auth_result.unwrap()
        assert identity.token```
______________________________________________________________________

## Future Integration Plans

### Modern Authentication Protocols

Plans for OAuth2 provider integration:

```python
from __future__ import annotations
from flext_auth import FlextAuth
from flext_core import m, p


# Future OAuth2 provider implementation
class OAuth2Provider:
    """OAuth2 provider using flext-auth foundation."""

    def __init__(self):
        self._auth = FlextAuth.quick_start(create_admin_user=False)

    def authorize(self, client_id: str, redirect_uri: str) -> p.Result[str]:
        """OAuth2 authorization endpoint."""
        # Implementation using flext-auth
        ...

    def token(self, code: str, client_id: str) -> p.Result[m.Dict]:
        """OAuth2 token endpoint."""
        # Implementation using flext-auth
        ...```
### Enterprise SSO

Plans for SAML integration:

```python
from __future__ import annotations
from flext_auth import FlextAuth, m as auth_m
from flext_core import p


# Future SAML integration
class SAMLProvider:
    """SAML service provider using flext-auth."""

    def __init__(self):
        self._auth = FlextAuth.quick_start(create_admin_user=False)

    def process_saml_response(
        self, saml_response: str
    ) -> p.Result[auth_m.Auth.AuthIdentity]:
        """Process SAML authentication response."""
        # Implementation using flext-auth
        ...```
______________________________________________________________________

This integration guide reflects the current implementation and planned integrations as of April 14, 2026.

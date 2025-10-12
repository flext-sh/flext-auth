# Integration

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

Integration patterns for flext-auth within the FLEXT ecosystem.

---

## Overview

flext-auth integrates with the FLEXT ecosystem through [flext-core](../../flext-core/README.md) foundation patterns and provides authentication services to other FLEXT projects.

**Integration Status**: 85% flext-core pattern compliance

---

## FLEXT-Core Integration

flext-auth follows **[flext-core](../../flext-core/README.md)** patterns. For complete FlextCore.Result usage patterns, see the flext-core documentation.

### Authentication-Specific Integration

Authentication operations return FlextCore.Result for consistency with FLEXT ecosystem:

```python
from flext_auth import FlextAuth

auth = FlextAuth()

# Basic authentication pattern
auth_result = auth.authenticate_user("username", "password")
if auth_result.is_success:
    session_data = auth_result.unwrap()
    print(f"Authentication successful: {session_data['user']['username']}")
else:
    print(f"Authentication failed: {auth_result.error}")

# Usage
result = authenticate_user_safely("demo", "password123")
if result.is_success:
    auth_info = result.unwrap()
    print(f"Authenticated user: {auth_info['user']}")
else:
    print(f"Authentication failed: {result.error}")
```

### FlextCore.Container Integration

Use FlextCore.Container for dependency injection:

```python
from flext_core import FlextCore
from flext_auth import FlextAuth, FlextAuthConfig

# Register authentication service
container = FlextCore.Container.get_global()

config = FlextAuthConfig()
auth_service = FlextAuth(config=config)
container.register("auth_service", auth_service)

# Use from container in other services
class UserService:
    def __init__(self):
        self._container = FlextCore.Container.get_global()
        self._auth = self._container.get("auth_service").unwrap()

    def create_authenticated_user(self, user_data: dict) -> FlextCore.Result[FlextCore.Types.Dict]:
        # Use injected auth service
        return self._auth.register_user(**user_data)
```

### Domain Modeling

All domain entities extend FlextCore.Models.Entity:

```python
from flext_core import FlextCore
from flext_auth.models import FlextAuthModels

# User entity follows FLEXT patterns
user = FlextAuthModels.User(
    username="demo",
    email="demo@example.com"
)

# Business logic returns FlextCore.Result
password_result = user.set_password("secure123")
if password_result.is_success:
    print("Password set successfully")
```

---

## Integration with FLEXT Projects

### flext-api Integration

Authentication middleware for REST APIs:

```python
# In flext-api project
from flext_auth import FlextAuth
from fastapi import Depends, HTTPException
from fastapi.security import HTTPBearer

auth = FlextAuth()
security = HTTPBearer()

def authenticate_request(token: str = Depends(security)):
    """Authentication middleware for FastAPI."""
    validation_result = auth.validate_token(token.credentials)

    if validation_result.is_failure:
        raise HTTPException(status_code=401, detail=validation_result.error)

    return validation_result.unwrap()

# Protected endpoint
@app.get("/protected")
def protected_endpoint(user_data=Depends(authenticate_request)):
    return {"message": f"Hello {user_data['username']}"}
```

### flext-web Integration

Web application authentication flows:

```python
# In flext-web project
from flask import session, request, redirect, url_for
from flext_auth import FlextAuth

auth = FlextAuth()

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']

    auth_result = auth.authenticate_user(username, password)

    if auth_result.is_success:
        auth_data = auth_result.unwrap()
        session['token'] = auth_data['token']
        session['user'] = auth_data['user']['username']
        return redirect(url_for('dashboard'))
    else:
        flash(f"Login failed: {auth_result.error}")
        return redirect(url_for('login_page'))

def require_auth(f):
    """Authentication decorator for Flask routes."""
    def decorated_function(*args, **kwargs):
        token = session.get('token')
        if not token:
            return redirect(url_for('login_page'))

        validation_result = auth.validate_token(token)
        if validation_result.is_failure:
            session.clear()
            return redirect(url_for('login_page'))

        return f(*args, **kwargs)
    return decorated_function
```

### flext-cli Integration

CLI authentication patterns:

```python
# In flext-cli project
import click
from flext_auth import FlextAuth

@click.group()
@click.pass_context
def cli(ctx):
    """CLI with authentication support."""
    ctx.ensure_object(dict)
    ctx.obj['auth'] = FlextAuth()

@cli.command()
@click.option('--username', prompt=True)
@click.option('--password', prompt=True, hide_input=True)
@click.pass_context
def login(ctx, username, password):
    """Authenticate user for CLI operations."""
    auth = ctx.obj['auth']
    result = auth.authenticate_user(username, password)

    if result.is_success:
        ctx.obj['token'] = result.unwrap()['token']
        click.echo("Authentication successful")
    else:
        click.echo(f"Authentication failed: {result.error}")
        ctx.exit(1)
```

---

## Service Integration Patterns

### Authentication Service Provider

flext-auth acts as authentication service provider for the ecosystem:

```python
class AuthenticationProvider:
    """Centralized authentication for FLEXT ecosystem."""

    def __init__(self):
        self._auth = FlextAuth()
        self._container = FlextCore.Container.get_global()

    def authenticate_service_request(self, token: str) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Authenticate requests from other FLEXT services."""
        return self._auth.validate_token(token)

    def create_service_token(self, service_name: str) -> FlextCore.Result[str]:
        """Create token for service-to-service authentication."""
        # Implementation for service tokens
        pass
```

### Inter-Service Authentication

Pattern for service-to-service authentication:

```python
# Service A calling Service B
class ServiceA:
    def __init__(self):
        self._auth = FlextAuth()
        self._service_token = self._get_service_token()

    def call_service_b(self, data: dict) -> FlextCore.Result[FlextCore.Types.Dict]:
        """Call Service B with authentication."""
        headers = {
            "Authorization": f"Bearer {self._service_token}",
            "Content-Type": "application/json"
        }

        # Make authenticated request to Service B
        response = requests.post(
            "http://service-b/api/endpoint",
            json=data,
            headers=headers
        )

        if response.status_code == 200:
            return FlextCore.Result[FlextCore.Types.Dict].ok(response.json())
        else:
            return FlextCore.Result[FlextCore.Types.Dict].fail(f"Service call failed: {response.text}")
```

---

## Database Integration

### User Storage (Future)

Integration with flext-db-oracle for user storage:

```python
# Future integration pattern
from flext_db_oracle import OracleRepository
from flext_auth.models import User

class UserRepository(OracleRepository[User]):
    """User storage using Oracle database."""

    def find_by_username(self, username: str) -> FlextCore.Result[User]:
        """Find user by username."""
        # Oracle-specific implementation
        pass

    def create_user(self, user: User) -> FlextCore.Result[User]:
        """Create user in database."""
        # Oracle-specific implementation
        pass
```

### Session Storage (Future)

Integration with Redis for session management:

```python
# Future integration pattern
import redis
from flext_auth.models import Session

class RedisSessionStorage:
    """Session storage using Redis."""

    def __init__(self):
        self._redis = redis.Redis(host='localhost', port=6379, db=0)

    def store_session(self, session: Session) -> FlextCore.Result[bool]:
        """Store session in Redis."""
        try:
            session_data = session.model_dump_json()
            self._redis.setex(
                session.session_token,
                session.expires_at.timestamp(),
                session_data
            )
            return FlextCore.Result[bool].ok(True)
        except Exception as e:
            return FlextCore.Result[bool].fail(f"Session storage failed: {e}")
```

---

## Configuration Integration

### Environment-Aware Configuration

Integration with FLEXT environment management:

```python
from flext_auth import FlextAuthConfig
import os

# Environment detection
flext_env = os.getenv("FLEXT_ENV", "development")

# Create environment-specific configuration
config_result = FlextAuthConfig()
if config_result.is_success:
    auth_config = config_result.unwrap()
    auth = FlextAuth(config=auth_config)
else:
    raise RuntimeError(f"Configuration failed: {config_result.error}")
```

### Shared Configuration

Integration with FLEXT workspace configuration:

```python
# Shared configuration across FLEXT services
from flext_core import FlextWorkspaceConfig

class FlextAuthWorkspaceConfig(FlextWorkspaceConfig):
    """Authentication configuration within FLEXT workspace."""

    def __init__(self):
        super().__init__()
        self.auth_config = FlextAuthConfig()

    def get_auth_service(self) -> FlextCore.Result[FlextAuth]:
        """Get configured authentication service."""
        if self.auth_config.is_success:
            return FlextCore.Result[FlextAuth].ok(FlextAuth(config=self.auth_config.unwrap()))
        else:
            return FlextCore.Result[FlextAuth].fail("Auth configuration failed")
```

---

## Testing Integration

### Integration Testing

Test authentication with other FLEXT services:

```python
import pytest
from flext_auth import FlextAuth
from flext_api import FlextApiService  # Example integration

class TestAuthIntegration:
    def test_auth_with_api_service(self):
        """Test authentication integration with API service."""
        # Arrange
        auth = FlextAuth()
        api_service = FlextApiService(auth=auth)

        # Act
        result = auth.register_user("test", "test@example.com", "password123")
        assert result.is_success

        auth_result = auth.authenticate_user("test", "password123")
        assert auth_result.is_success

        token = auth_result.unwrap()['token']

        # Test API service with token
        api_result = api_service.authenticate_request(token)
        assert api_result.is_success
```

---

## Future Integration Plans

### Modern Authentication Protocols

Plans for OAuth2/OIDC integration:

```python
# Future OAuth2 provider implementation
class OAuth2Provider:
    """OAuth2 provider using flext-auth foundation."""

    def __init__(self):
        self._auth = FlextAuth()

    def authorize(self, client_id: str, redirect_uri: str) -> FlextCore.Result[str]:
        """OAuth2 authorization endpoint."""
        # Implementation using flext-auth
        pass

    def token(self, code: str, client_id: str) -> FlextCore.Result[FlextCore.Types.Dict]:
        """OAuth2 token endpoint."""
        # Implementation using flext-auth
        pass
```

### Enterprise SSO

Plans for SAML integration:

```python
# Future SAML integration
class SAMLProvider:
    """SAML service provider using flext-auth."""

    def __init__(self):
        self._auth = FlextAuth()

    def process_saml_response(self, saml_response: str) -> FlextCore.Result[User]:
        """Process SAML authentication response."""
        # Implementation using flext-auth
        pass
```

---

This integration guide reflects the current implementation and planned integrations as of September 17, 2025.

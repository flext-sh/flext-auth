# API Reference

<!-- TOC START -->

- [Core API](#core-api)
  - [flext_auth_quick_start()](#flextauthquickstart)
- [FlextAuth Service](#flextauth-service)
  - [Constructor](#constructor)
  - [register_user()](#registeruser)
  - [authenticate_user()](#authenticateuser)
  - [validate_token()](#validatetoken)
- [Domain Models](#domain-models)
  - [User](#user)
  - [Session](#session)
  - [UserCreationRequest](#usercreationrequest)
- [Configuration](#configuration)
  - [FlextAuthSettings](#flextauthsettings)
- [CLI Interface](#cli-interface)
  - [create-user](#create-user)
  - [authenticate](#authenticate)
  - [validate-config](#validate-config)
- [Error Handling](#error-handling)
  - [Success Pattern](#success-pattern)
  - [Chaining Pattern](#chaining-pattern)
- [Integration with FLEXT Ecosystem](#integration-with-flext-ecosystem)
  - [Container Integration](#container-integration)
  - [r Usage](#flextresult-usage)
- [Security Considerations](#security-considerations)
  - [Password Security](#password-security)
  - [JWT Security](#jwt-security)
  - [Session Management](#session-management)
- [Related Documentation](#related-documentation)

<!-- TOC END -->

**Version**: 1.0.0 Production Ready | **Updated**: October 1, 2025

Complete API documentation for flext-auth enterprise authentication service with FlextService and h architecture.

For general FLEXT patterns and r usage, see **[flext-core](https://github.com/organization/flext/tree/main/flext-core/README.md)** documentation.

**Note**: This API is 100% backward compatible. All existing code continues to work unchanged after the h refactoring.

______________________________________________________________________

## Core API

### flext_auth_quick_start()

Initialize authentication service for development and testing.

```python
from flext_auth import flext_auth_quick_start

auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
```

**Parameters**:

- `create_REDACTED_LDAP_BIND_PASSWORD` (bool): Create default REDACTED_LDAP_BIND_PASSWORD user (default: False)

**Returns**: `FlextAuth` instance

______________________________________________________________________

## FlextAuth Service

### Constructor

```python
from flext_auth import FlextAuth, FlextAuthSettings

config = FlextAuthSettings()
auth = FlextAuth(config=config)
```

### register_user()

Register a new user with username, email, and password.

```python
def register_user(
    self,
    username: str,
    email: str,
    password: str
) -> r[User]:
```

**Parameters**:

- `username` (str): Unique username
- `email` (str): Valid email address
- `password` (str): User password (will be hashed with bcrypt)

**Returns**: `r[User]` - Created user or error

**Example**:

```python
result = auth.register_user("demo", "demo@example.com", "secure123")
if result.is_success:
    user = result.unwrap()
    print(f"User created: {user.username}")
```

### authenticate_user()

Authenticate user with username and password.

```python
def authenticate_user(
    self,
    username: str,
    password: str
) -> r[t.Dict]:
```

**Parameters**:

- `username` (str): Username to authenticate
- `password` (str): User password

**Returns**: `r[t.Dict]` with session and token data

**Example**:

```python
auth_result = auth.authenticate_user("demo", "secure123")
if auth_result.is_success:
    session_data = auth_result.unwrap()
    token = session_data["token"]
    session = session_data["session"]
```

### validate_token()

Validate JWT token and extract user information.

```python
def validate_token(self, token: str) -> r[t.Dict]:
```

**Parameters**:

- `token` (str): JWT token (with or without Bearer prefix)

**Returns**: `r[t.Dict]` with token payload or error

**Example**:

```python
validation_result = auth.validate_token(token)
if validation_result.is_success:
    token_data = validation_result.unwrap()
    username = token_data["username"]
```

______________________________________________________________________

## Domain Models

### User

User entity extending FlextModels.Entity.

```python
class User(FlextModels.Entity):
    username: str
    email: str
    password_hash: str
    roles: t.StringList
    created_at: datetime
    is_active: bool = True
```

**Methods**:

#### set_password()

```python
def set_password(self, password: str) -> r[bool]:
```

Hash and set user password using bcrypt.

#### verify_password()

```python
def verify_password(self, password: str) -> r[bool]:
```

Verify password against stored hash.

### Session

Session entity for managing user sessions.

```python
class Session(FlextModels.Entity):
    user_id: str
    session_token: str
    expires_at: datetime
    is_active: bool = True
```

### UserCreationRequest

Request model for user registration.

```python
class UserCreationRequest(BaseModel):
    username: str
    email: str
    password: str
    full_name: str | None = None
    roles: t.StringList = Field(default_factory=list)
```

______________________________________________________________________

## Configuration

### FlextAuthSettings

Configuration class extending FlextSettings.

```python
class FlextAuthSettings(FlextSettings):
    # JWT Settings
    jwt_secret_key: str = "dev-secret-key"
    jwt_expiry_minutes: int = 60
    jwt_algorithm: str = "HS256"

    # Security Settings
    bcrypt_rounds: int = 12
    max_failed_attempts: int = 5
    session_timeout_minutes: int = 120
```

#### create_for_environment()

```python
@classmethod
def create_for_environment(cls, env: str) -> r[FlextAuthSettings]:
```

Create configuration for specific environment.

**Parameters**:

- `env` (str): Environment name ("development", "production", etc.)

**Example**:

```python
config_result = FlextAuthSettings()
if config_result.is_success:
    config = config_result.unwrap()
```

______________________________________________________________________

## CLI Interface

### create-user

Create user via command line.

```bash
flext-auth create-user \
    --username alice \
    --email alice@example.com \
    --password securepass123
```

### authenticate

Test user authentication.

```bash
flext-auth authenticate \
    --username alice \
    --password securepass123
```

### validate-config

Validate current configuration.

```bash
flext-auth validate-config
```

______________________________________________________________________

## Error Handling

All operations return `r[T]` for type-safe error handling.

### Success Pattern

```python
result = auth.register_user("demo", "demo@example.com", "secure123")
if result.is_success:
    user = result.unwrap()
    # Use user object
else:
    print(f"Error: {result.error}")
```

### Chaining Pattern

```python
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import t
from flext_core import u


def complete_auth_flow(username: str, password: str) -> r[t.Dict]:
    return (
        auth
        .authenticate_user(username, password)
        .flat_map(lambda auth_data: auth.validate_token(auth_data["token"]))
        .map(
            lambda token_data: {
                "user": token_data["username"],
                "authenticated": True,
                "expires": token_data["exp"],
            }
        )
    )
```

______________________________________________________________________

## Integration with FLEXT Ecosystem

### Container Integration

```python
from flext_core import FlextBus
from flext_core import FlextSettings
from flext_core import FlextConstants
from flext_core import FlextContainer
from flext_core import FlextContext
from flext_core import FlextDecorators
from flext_core import FlextDispatcher
from flext_core import FlextExceptions
from flext_core import h
from flext_core import FlextLogger
from flext_core import x
from flext_core import FlextModels
from flext_core import FlextProcessors
from flext_core import p
from flext_core import FlextRegistry
from flext_core import r
from flext_core import FlextRuntime
from flext_core import FlextService
from flext_core import t
from flext_core import u

container = FlextContainer.get_global()
container.register("auth_service", auth)

auth_result = container.get("auth_service")
if auth_result.is_success:
    auth = auth_result.unwrap()
```

### r Usage

All flext-auth operations follow r pattern from flext-core:

- Use `.is_success` to check success
- Use `.unwrap()` to extract value on success
- Use `.error` to get error message on failure
- Chain operations with `.flat_map()` and `.map()`

______________________________________________________________________

## Security Considerations

### Password Security

- Passwords are hashed using bcrypt with 12 rounds
- Original passwords are never stored
- Password verification uses constant-time comparison

### JWT Security

- Tokens signed with HMAC SHA-256 algorithm
- Configurable expiration times
- Bearer token format support
- Signature validation on all token operations

### Session Management

- Sessions have configurable timeout
- Session tokens are cryptographically secure
- Expired sessions are automatically invalid

______________________________________________________________________

This API reference covers the current implementation as of September 17, 2025. For usage examples, see Getting Started.

## Related Documentation

**Within Project**:

- Getting Started - Installation and basic usage
- Architecture - Architecture and design patterns
- Configuration - Settings management
- Integration - FLEXT ecosystem patterns

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-core Railway-Oriented Programming](https://github.com/organization/flext/tree/main/flext-core/docs/guides/railway-oriented-programming.md) - r patterns
- [flext-cli Authentication](https://github.com/organization/flext/tree/main/flext-cli/docs/api-reference.md) - CLI authentication patterns

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

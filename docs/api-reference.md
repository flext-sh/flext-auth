# API Reference

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

Complete API documentation for flext-auth authentication service.

For general FLEXT patterns and FlextResult usage, see **[flext-core](../../flext-core/README.md)** documentation.

---

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

---

## FlextAuth Service

### Constructor

```python
from flext_auth import FlextAuth, FlextAuthConfig

config = FlextAuthConfig.create_for_environment("development").unwrap()
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
) -> FlextResult[User]:
```

**Parameters**:

- `username` (str): Unique username
- `email` (str): Valid email address
- `password` (str): User password (will be hashed with bcrypt)

**Returns**: `FlextResult[User]` - Created user or error

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
) -> FlextResult[dict]:
```

**Parameters**:

- `username` (str): Username to authenticate
- `password` (str): User password

**Returns**: `FlextResult[dict]` with session and token data

**Example**:

```python
auth_result = auth.authenticate_user("demo", "secure123")
if auth_result.is_success:
    session_data = auth_result.unwrap()
    token = session_data['token']
    session = session_data['session']
```

### validate_token()

Validate JWT token and extract user information.

```python
def validate_token(self, token: str) -> FlextResult[dict]:
```

**Parameters**:

- `token` (str): JWT token (with or without Bearer prefix)

**Returns**: `FlextResult[dict]` with token payload or error

**Example**:

```python
validation_result = auth.validate_token(token)
if validation_result.is_success:
    token_data = validation_result.unwrap()
    username = token_data['username']
```

---

## Domain Models

### User

User entity extending FlextModels.Entity.

```python
class User(FlextModels.Entity):
    username: str
    email: str
    password_hash: str
    roles: list[str]
    created_at: datetime
    is_active: bool = True
```

**Methods**:

#### set_password()

```python
def set_password(self, password: str) -> FlextResult[bool]:
```

Hash and set user password using bcrypt.

#### verify_password()

```python
def verify_password(self, password: str) -> FlextResult[bool]:
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
    roles: list[str] = Field(default_factory=list)
```

---

## Configuration

### FlextAuthConfig

Configuration class extending FlextConfig.

```python
class FlextAuthConfig(FlextConfig):
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
def create_for_environment(cls, env: str) -> FlextResult[FlextAuthConfig]:
```

Create configuration for specific environment.

**Parameters**:

- `env` (str): Environment name ("development", "production", etc.)

**Example**:

```python
config_result = FlextAuthConfig.create_for_environment("production")
if config_result.is_success:
    config = config_result.unwrap()
```

---

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

---

## Error Handling

All operations return `FlextResult[T]` for type-safe error handling.

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
from flext_core import FlextResult

def complete_auth_flow(username: str, password: str) -> FlextResult[dict]:
    return (
        auth.authenticate_user(username, password)
        .flat_map(lambda auth_data: auth.validate_token(auth_data['token']))
        .map(lambda token_data: {
            "user": token_data['username'],
            "authenticated": True,
            "expires": token_data['exp']
        })
    )
```

---

## Integration with FLEXT Ecosystem

### Container Integration

```python
from flext_core import FlextContainer

container = FlextContainer.get_global()
container.register("auth_service", auth)

auth_result = container.get("auth_service")
if auth_result.is_success:
    auth = auth_result.unwrap()
```

### FlextResult Usage

All flext-auth operations follow FlextResult pattern from flext-core:

- Use `.is_success` to check success
- Use `.unwrap()` to extract value on success
- Use `.error` to get error message on failure
- Chain operations with `.flat_map()` and `.map()`

---

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

---

This API reference covers the current implementation as of September 17, 2025. For usage examples, see [Getting Started](getting-started.md).

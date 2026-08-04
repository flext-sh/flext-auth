# API Reference

<!-- TOC START -->
- [Core API](#core-api)
  - [FlextAuth.quick_start()](#flextauthquickstart)
- [FlextAuth Service](#flextauth-service)
  - [Constructor](#constructor)
  - [register_user()](#registeruser)
  - [authenticate_user()](#authenticateuser)
  - [authenticate()](#authenticate)
- [Domain Models](#domain-models)
  - [AuthIdentity](#authidentity)
  - [Session](#session)
  - [UserCreationRequest](#usercreationrequest)
- [Configuration](#configuration)
  - [FlextAuthSettings](#flextauthsettings)
- [CLI Interface](#cli-interface)
  - [create-user](#create-user)
  - [authenticate](#authenticate)
  - [validate-settings](#validate-settings)
- [Error Handling](#error-handling)
  - [Success Pattern](#success-pattern)
  - [Chaining Pattern](#chaining-pattern)
- [Integration with FLEXT Ecosystem](#integration-with-flext-ecosystem)
  - [Container Integration](#container-integration)
  - [r Usage](#r-usage)
- [Security Considerations](#security-considerations)
  - [Password Security](#password-security)
  - [JWT Security](#jwt-security)
  - [Session Management](#session-management)
- [Related Documentation](#related-documentation)
<!-- TOC END -->

**Version**: 0.12.0-dev Current | **Updated**: April 14, 2026

Complete API documentation for the flext-auth enterprise authentication service.

For general FLEXT patterns and `r` usage, see the
**[flext-core](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/README.md)**
documentation.

______________________________________________________________________

## Core API

### FlextAuth.quick_start()

Initialize the authentication service for development and testing.

```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_admin_user=False)```
**Parameters**:

- `create_admin_user` (bool): Create the default admin user (default: True)

**Returns**: `FlextAuth` instance

______________________________________________________________________

## FlextAuth Service

### Constructor

```python
from flext_auth import FlextAuth, FlextAuthSettings

settings = FlextAuthSettings()
auth = FlextAuth(settings=settings)```
### register_user()

Register a new user with username, email, and password.

```python
from __future__ import annotations


def register_user(
    self,
    username: str,
    email: str,
    password: str,
    roles: t.StrSequence | None = None,
    role: str | None = None,
) -> p.Result[m.Auth.AuthIdentity]: ...```
**Parameters**:

- `username` (str): Unique username
- `email` (str): Valid email address
- `password` (str): User password (will be hashed with bcrypt)
- `roles` (t.StrSequence | None): Optional role sequence
- `role` (str | None): Optional single role

**Returns**: `r[m.Auth.AuthIdentity]` - Created identity or error

**Example**:

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)
result = auth.register_user("demo", "demo@example.com", "secure123")
if result.success:
    user = result.unwrap()
    u.Cli.info(f"User created: {user.name}")```
### authenticate_user()

Authenticate a user with username and password.

```python
from __future__ import annotations


def authenticate_user(
    self,
    username: str,
    password: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> p.Result[m.Auth.AuthIdentity]: ...```
**Parameters**:

- `username` (str): Username to authenticate
- `password` (str): User password
- `ip_address` (str | None): Optional client IP
- `user_agent` (str | None): Optional client user agent

**Returns**: `r[m.Auth.AuthIdentity]` with identity and token data

**Example**:

```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_admin_user=False)
auth_result = auth.authenticate_user("demo", "secure123")
if auth_result.success:
    identity = auth_result.unwrap()
    token = identity.token
    session_id = identity.session_id```
### authenticate()

Authenticate with a credentials mapping.

```python
from __future__ import annotations


def authenticate(self, credentials: t.StrMapping) -> p.Result[m.Auth.AuthIdentity]: ...```
**Example**:

```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_admin_user=False)
result = auth.authenticate({"username": "demo", "password": "secure123"})
if result.success:
    identity = result.unwrap()
    u.Cli.info(f"Authenticated: {identity.name}")```
______________________________________________________________________

## Domain Models

### AuthIdentity

Authentication identity extending `FlextModels.Entity`.

```python
from __future__ import annotations
from flext_auth import m


class AuthIdentity(m.BaseModel):
    name: str
    contact: str
    credential_hash: str
    roles: t.StrSequence
    is_active: bool = True```
**Methods**:

#### set_password()

```python
from __future__ import annotations


def set_password(self, password: str) -> p.Result[bool]: ...```
Hash and set the user password using bcrypt.

#### verify_password()

```python
from __future__ import annotations


def verify_password(self, password: str) -> p.Result[bool]: ...```
Verify the password against the stored hash.

### Session

Session model for managing user sessions.

```python
from __future__ import annotations
from flext_auth import m


class Session(m.BaseModel):
    user_id: str
    session_token: str
    expires_at: datetime
    is_active: bool = True```
### UserCreationRequest

Request model for user registration.

```python
from __future__ import annotations
from flext_core import m, t
from flext_cli import u


class UserCreationRequest(m.BaseModel):
    username: str
    email: str
    password: str
    full_name: str | None = None
    roles: t.StrSequence = u.Field(default_factory=list)```
______________________________________________________________________

## Configuration

### FlextAuthSettings

Configuration class extending `FlextSettings`.

```text
from __future__ import annotations
from flext_core import m
from flext_cli import u


class FlextAuthSettings(FlextSettings):
    Auth: AuthSettings
```

JWT and security settings are available under `settings.Auth`:

- `secret_key` (str): JWT signing secret
- `algorithm` (str): JWT signing algorithm
- `expiry_minutes` (int): Access token lifetime in minutes
- `session_expiry_minutes` (int): Session lifetime in minutes
- `hash_rounds` (int): Bcrypt hashing rounds
- `max_sessions_per_user` (int): Maximum sessions per user

#### create_for_environment()

```python
from __future__ import annotations


@classmethod
def create_for_environment(cls, env: str) -> p.Result[FlextAuthSettings]: ...```
Create configuration for a specific environment.

**Parameters**:

- `env` (str): Environment name ("development", "production", etc.)

**Example**:

```python
from flext_auth import FlextAuthSettings

settings = FlextAuthSettings()```
______________________________________________________________________

## CLI Interface

### create-user

Create a user via the command line.

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

### validate-settings

Validate the current configuration.

```bash
flext-auth validate-settings
```

______________________________________________________________________

## Error Handling

All operations return `r[T]` for type-safe error handling.

### Success Pattern

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)
result = auth.register_user("demo", "demo@example.com", "secure123")
if result.success:
    user = result.unwrap()
    u.Cli.info(f"User created: {user.name}")
else:
    u.Cli.info(f"Error: {result.error}")```
### Chaining Pattern

```python
from __future__ import annotations
from flext_auth import FlextAuth
from flext_core import m, p


auth = FlextAuth.quick_start(create_admin_user=False)


def complete_auth_flow(username: str, password: str) -> p.Result[m.Auth.AuthIdentity]:
    return auth.authenticate_user(username, password)```
______________________________________________________________________

## Integration with FLEXT Ecosystem

### Container Integration

```python
from flext_auth import FlextAuth, FlextAuthSettings
from flext_core import FlextContainer
from flext_cli import u

auth = FlextAuth(settings=FlextAuthSettings())
container = FlextContainer()
container.bind("auth_service", auth)

auth_result = container.resolve("auth_service")
if auth_result.success:
    service = auth_result.unwrap()
    u.Cli.info("Authentication service resolved")
```

### r Usage

All flext-auth operations follow the `r` pattern from flext-core:

- Use `.success` to check success
- Use `.unwrap()` to extract the value on success
- Use `.error` to get the error message on failure
- Chain operations with `.flat_map()` and `.map()`

______________________________________________________________________

## Security Considerations

### Password Security

- Passwords are hashed using bcrypt with configurable rounds
- Original passwords are never stored
- Password verification uses constant-time comparison

### JWT Security

- Tokens are signed with HMAC SHA-256 by default
- Configurable expiration times
- Bearer token format support
- Signature validation on all token operations

### Session Management

- Sessions have configurable timeouts
- Session tokens are cryptographically secure
- Expired sessions are automatically invalid

______________________________________________________________________

This API reference covers the current implementation as of April 14, 2026.
For usage examples, see Getting Started.

## Related Documentation

**Within Project**:

- Getting Started - Installation and basic usage
- Architecture - Architecture and design patterns
- Configuration - Settings management
- Integration - FLEXT ecosystem patterns

**Across Projects**:

- [flext-core Foundation](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/docs/api-reference/foundation.md) - Core APIs and patterns
- [flext-core Railway-Oriented Programming](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/docs/guides/railway-oriented-programming.md) - r patterns
- [flext-cli Authentication](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-cli/docs/api-reference.md) - CLI authentication patterns

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

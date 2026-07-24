# Getting Started

<!-- TOC START -->
- [Installation](#installation)
  - [Prerequisites](#prerequisites)
  - [Installation](#installation)
- [Basic Authentication](#basic-authentication)
  - [Quick Start Service](#quick-start-service)
  - [User Authentication](#user-authentication)
  - [Token Validation](#token-validation)
- [Configuration](#configuration)
  - [Environment Configuration](#environment-configuration)
  - [Custom Configuration](#custom-configuration)
- [CLI Usage](#cli-usage)
  - [User Management](#user-management)
  - [Configuration Management](#configuration-management)
- [FLEXT Integration Patterns](#flext-integration-patterns)
  - [r Error Handling](#r-error-handling)
  - [Container Integration](#container-integration)
- [Domain Models](#domain-models)
  - [Working with User Entities](#working-with-user-entities)
  - [Session Management](#session-management)
- [Testing Your Integration](#testing-your-integration)
  - [Unit Testing with r](#unit-testing-with-r)
- [Next Steps](#next-steps)
  - [Development Environment](#development-environment)
  - [Documentation](#documentation)
  - [Production Considerations](#production-considerations)
- [Related Documentation](#related-documentation)
<!-- TOC END -->

**Version**: 1.0.0 Current | **Updated**: October 1, 2025

Installation and first steps for implementing enterprise authentication in your FLEXT projects using flext-auth with complete s and h integration.

______________________________________________________________________

## Installation

### Prerequisites

- Python 3.13+
- Poetry for dependency management
- **[flext-core](https://github.com/organization/flext/tree/main/flext-core/README.md)** foundation library

### Installation

```bash
# Navigate to flext-auth directory
cd flext-auth

# Install dependencies
poetry install

# Verify installation
python -c "from flext_auth import flext_auth_quick_start; u.Cli.print('flext-auth ready')"
```

______________________________________________________________________

## Basic Authentication

### Quick Start Service

```python
from flext_auth import flext_auth_quick_start, FlextAuthModels

# Initialize authentication service
auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

# Create user request t.JsonValue
user_request = FlextAuthModels.UserCreationRequest(
    username="alice", email="alice@example.com", password="secure123"
)

# Register user (r pattern)
result = auth.register_user(
    username=user_request.username,
    email=user_request.email,
    password=user_request.password,
)

if result.success:
    user = result.unwrap()
    u.Cli.print(f"User created: {user.username}")
else:
    u.Cli.print(f"Registration failed: {result.error}")
```

### User Authentication

```python
# Authenticate user
auth_result = auth.authenticate_user("alice", "secure123")

if auth_result.success:
    session_data = auth_result.unwrap()
    u.Cli.print("Authentication successful")
    u.Cli.print(f"Session: {session_data['session']['id']}")
    u.Cli.print(f"Token: {session_data['token']}")
else:
    u.Cli.print(f"Authentication failed: {auth_result.error}")
```

### Token Validation

```python
# Validate JWT token
token = "your-jwt-token-here"
validation_result = auth.validate_token(token)

if validation_result.success:
    token_data = validation_result.unwrap()
    u.Cli.print(f"Token valid for user: {token_data['username']}")
else:
    u.Cli.print(f"Token invalid: {validation_result.error}")
```

______________________________________________________________________

## Configuration

### Environment Configuration

```python
from flext_auth import FlextAuthSettings

# Development configuration
settings = FlextAuthSettings()

if settings.success:
    dev_config = settings.unwrap()
    u.Cli.print(f"JWT expiry: {dev_config.jwt_expiry_minutes} minutes")
    u.Cli.print(f"bcrypt rounds: {dev_config.bcrypt_rounds}")
```

### Custom Configuration

```python
from flext_auth import FlextAuth, FlextAuthSettings

# Custom configuration
settings = FlextAuthSettings(
    jwt_expiry_minutes=30,  # 30-minute tokens
    bcrypt_rounds=14,  # Higher security
    max_failed_attempts=3,  # Account lockout
    session_timeout_minutes=60,  # 1-hour sessions
)

# Use custom configuration
auth = FlextAuth(settings=settings)
```

______________________________________________________________________

## CLI Usage

### User Management

```bash
# Create user via CLI
flext-auth create-user \
    --username bob \
    --email bob@example.com \
    --password securepass456

# Authenticate user
flext-auth authenticate \
    --username bob \
    --password securepass456
```

### Configuration Management

```bash
# Validate current configuration
flext-auth validate-settings

# Show configuration summary
flext-auth manage-settings show
```

______________________________________________________________________

## FLEXT Integration Patterns

### r Error Handling

```python
from __future__ import annotations
from flext_cli import u
from flext_core import FlextSettings


def process_authentication_workflow(username: str, password: str) -> p.Result[m.Dict]:
    """Authentication workflow using r error handling."""

    auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    # Chain operations with r
    return (
        auth
        .authenticate_user(username, password)
        .flat_map(lambda auth_data: auth.validate_token(auth_data["token"]))
        .map(
            lambda token_data: {
                "authenticated": True,
                "user": token_data["username"],
                "expires": token_data["exp"],
            }
        )
    )


# Usage
result = process_authentication_workflow("alice", "secure123")
if result.success:
    data = result.unwrap()
    u.Cli.print(f"User {data['user']} authenticated until {data['expires']}")
```

### Container Integration

```python
from flext_cli import u
from flext_core import FlextSettings
from flext_auth import FlextAuth, FlextAuthSettings

# Register authentication service in container
container = FlextContainer.get_global()

# Configure and register
settings = FlextAuthSettings()
auth_service = FlextAuth(settings=settings)
container.bind("auth_service", auth_service)

# Use from container
auth_result = container.resolve("auth_service")
if auth_result.success:
    auth = auth_result.unwrap()
    # Use authentication service
```

______________________________________________________________________

## Domain Models

### Working with User Entities

```python
from flext_auth import FlextAuthModels

# Create user entity
user = FlextAuthModels.User(
    username="charlie",
    email="charlie@example.com",
    roles=["user", "REDACTED_LDAP_BIND_PASSWORD"],
)

# Set password (bcrypt hashing)
password_result = user.set_password("mypassword")
if password_result.success:
    u.Cli.print("Password set successfully")

# Verify password
verification_result = user.verify_password("mypassword")
if verification_result.success and verification_result.unwrap():
    u.Cli.print("Password verification successful")
```

### Session Management

```python
from datetime import datetime, timedelta

# Create session
session = FlextAuthModels.Session(
    user_id=user.id,
    session_token="session-token-123",
    expires_at=datetime.utcnow() + timedelta(hours=2),
)

# Check session validity
if session.is_active and datetime.utcnow() < session.expires_at:
    u.Cli.print("Session is valid")
```

______________________________________________________________________

## Testing Your Integration

### Unit Testing with r

```python
from __future__ import annotations
import pytest
from flext_auth import flext_auth_quick_start


def test_authentication_workflow():
    """Test complete authentication workflow."""
    auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    # Register test user
    register_result = auth.register_user(
        username="testuser", email="test@example.com", password="testpass123"
    )

    assert register_result.success
    user = register_result.unwrap()
    assert user.username == "testuser"

    # Authenticate user
    auth_result = auth.authenticate_user("testuser", "testpass123")
    assert auth_result.success

    session_data = auth_result.unwrap()
    assert "token" in session_data
    assert "session" in session_data

    # Validate token
    token_result = auth.validate_token(session_data["token"])
    assert token_result.success
```

______________________________________________________________________

## Next Steps

### Development Environment

```bash
# Run tests
make test

# Code quality checks
make lint
make type-check

# Complete validation
make val
```

### Documentation

- **Architecture** - System design and patterns
- **API Reference** - Complete API documentation
- **Configuration** - Settings management
- **Integration** - FLEXT ecosystem patterns

### Production Considerations

- Review security settings for production deployment
- Configure external storage (database, Redis)
- Implement monitoring and logging
- Set up proper secret management

______________________________________________________________________

This guide covers basic usage patterns. For production deployment and additional features, see the documentation.

## Related Documentation

**Within Project**:

- Architecture - Architecture and design patterns
- API Reference - Complete API documentation
- Configuration - Settings management
- Integration - FLEXT ecosystem patterns

**Across Projects**:

- [flext-core Foundation](https://github.com/organization/flext/tree/main/flext-core/docs/architecture/overview.md) - Clean architecture and CQRS patterns
- [flext-core Service Patterns](https://github.com/organization/flext/tree/main/flext-core/docs/guides/service-patterns.md) - Service patterns and dependency injection
- [flext-cli Authentication](https://github.com/organization/flext/tree/main/flext-cli/docs/api-reference.md) - CLI authentication patterns

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

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

**Version**: 0.12.0-dev | **Updated**: April 14, 2026

Installation and first steps for implementing enterprise authentication in your FLEXT projects using flext-auth with complete FLEXT integration.

______________________________________________________________________

## Installation

### Prerequisites

- Python 3.13+
- uv for dependency management
- **[flext-core](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/README.md)** foundation library

### Installation

```bash
# Navigate to flext-auth directory
cd flext-auth

# Install dependencies
uv sync

# Verify installation
uv run python -c "from flext_auth import FlextAuth; print('flext-auth ready')"
```

______________________________________________________________________

## Basic Authentication

### Quick Start Service

```python
from flext_auth import FlextAuth
from flext_cli import u

# Initialize authentication service
auth = FlextAuth.quick_start(create_admin_user=False)

# Register user using the r pattern
result = auth.register_user(
    username="alice", email="alice@example.com", password="secure123"
)

if result.success:
    identity = result.unwrap()
    u.Cli.info(f"User created: {identity.name}")
else:
    u.Cli.info(f"Registration failed: {result.error}")```
### User Authentication

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)

# Authenticate user
auth_result = auth.authenticate_user("alice", "secure123")

if auth_result.success:
    identity = auth_result.unwrap()
    u.Cli.info("Authentication successful")
    u.Cli.info(f"Session ID: {identity.session_id}")
    u.Cli.info(f"Token: {identity.token}")
else:
    u.Cli.info(f"Authentication failed: {auth_result.error}")```
### Token Validation

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)

# Create a token via authentication
token_result = auth.create_token("identity-id")

if token_result.success:
    token = token_result.unwrap()
    u.Cli.info(f"Token created: {token}")
else:
    u.Cli.info(f"Token creation failed: {token_result.error}")```
______________________________________________________________________

## Configuration

### Environment Configuration

```python
from flext_auth import FlextAuthSettings
from flext_cli import u

settings = FlextAuthSettings()

u.Cli.info(f"JWT expiry: {settings.Auth.expiry_minutes} minutes")
u.Cli.info(f"bcrypt rounds: {settings.Auth.hash_rounds}")```
### Custom Configuration

```python
from flext_auth import FlextAuth, FlextAuthSettings

# Custom configuration
settings = FlextAuthSettings(
    Auth={
        "secret_key": "your-secret-key-with-at-least-32-characters",
        "expiry_minutes": 30,  # 30-minute tokens
        "hash_rounds": 14,  # Higher security
        "session_expiry_minutes": 60,  # 1-hour sessions
    }
)

# Use custom configuration
auth = FlextAuth(settings=settings)```
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
from flext_auth import FlextAuth
from flext_cli import u
from flext_core import m, p, r

auth = FlextAuth.quick_start(create_admin_user=False)


def process_authentication_workflow(username: str, password: str) -> p.Result[m.Dict]:
    """Authentication workflow using r error handling."""
    result = auth.authenticate_user(username, password)
    if result.failure:
        return r[m.Dict].fail(result.error)

    identity = result.unwrap()
    token_result = auth.create_token(identity.unique_id)
    if token_result.failure:
        return r[m.Dict].fail(token_result.error)

    return r[m.Dict].ok({
        "authenticated": True,
        "user": identity.name,
        "token": token_result.unwrap(),
    })


# Usage
result = process_authentication_workflow("alice", "secure123")
if result.success:
    data = result.unwrap()
    u.Cli.info(f"User {data['user']} authenticated")```
### Container Integration

```python notest
from flext_cli import u
from flext_core import FlextContainer, FlextSettings
from flext_auth import FlextAuth, FlextAuthSettings

# Register authentication service in container
container = FlextContainer()

# Configure and register
settings = FlextAuthSettings()
auth_service = FlextAuth(settings=settings)
container.bind("auth_service", auth_service)

# Use from container
auth_result = container.resolve("auth_service")
if auth_result.success:
    auth = auth_result.unwrap()
    u.Cli.info("Authentication service resolved")
```

______________________________________________________________________

## Domain Models

### Working with User Entities

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)

# Create an identity through the service
result = auth.register_user(
    username="charlie",
    email="charlie@example.com",
    password="secure123",
    roles=["user"],
)

if result.success:
    identity = result.unwrap()
    u.Cli.info(f"Identity created: {identity.name}")```
### Session Management

```python
from __future__ import annotations
from datetime import datetime, UTC

from flext_auth import m as auth_m
from flext_cli import u

# Create session
session = auth_m.Auth.Session(
    identity_id="user-id",
    session_token="session-token-123",
    expires_at=datetime.now(UTC),
)

# Check session validity
if session.is_active:
    u.Cli.info("Session is valid")```
______________________________________________________________________

## Testing Your Integration

### Unit Testing with r

```python
from __future__ import annotations

from flext_auth import FlextAuth


def test_authentication_workflow():
    """Test complete authentication workflow."""
    auth = FlextAuth.quick_start(create_admin_user=False)

    # Register test user
    register_result = auth.register_user(
        username="testuser", email="test@example.com", password="testpass123"
    )

    assert register_result.success
    identity = register_result.unwrap()
    assert identity.name == "testuser"

    # Authenticate user
    auth_result = auth.authenticate_user("testuser", "testpass123")
    assert auth_result.success

    identity = auth_result.unwrap()
    assert identity.token
    assert identity.session_id

    # Create token
    token_result = auth.create_token(identity.unique_id)
    assert token_result.success```
______________________________________________________________________

## Next Steps

### Development Environment

```bash
# Run tests
make test

# Code quality checks
make check

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

- [flext-core Foundation](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/docs/architecture/overview.md) - Clean architecture and CQRS patterns
- [flext-core Service Patterns](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/docs/guides/service-patterns.md) - Service patterns and dependency injection
- [flext-cli Authentication](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-cli/docs/api-reference.md) - CLI authentication patterns

**External Resources**:

- [PEP 257 - Docstring Conventions](https://peps.python.org/pep-0257/)
- [Google Python Style Guide](https://google.github.io/styleguide/pyguide.html)

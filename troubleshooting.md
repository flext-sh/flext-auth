# Troubleshooting

<!-- TOC START -->
- [Authentication Issues](#authentication-issues)
  - [User Registration Failures](#user-registration-failures)
  - [Authentication Failures](#authentication-failures)
  - [Token Validation Issues](#token-validation-issues)
- [Configuration Issues](#configuration-issues)
  - [Environment Configuration](#environment-configuration)
  - [JWT Configuration](#jwt-configuration)
- [Testing Issues](#testing-issues)
  - [Test Failures](#test-failures)
  - [Test Environment Setup](#test-environment-setup)
- [Performance Issues](#performance-issues)
  - [Slow Authentication](#slow-authentication)
  - [Memory Usage](#memory-usage)
- [Development Issues](#development-issues)
  - [IDE and Type Checking](#ide-and-type-checking)
  - [Import Issues](#import-issues)
- [Production Issues](#production-issues)
  - [Security Concerns](#security-concerns)
  - [Session Management](#session-management)
- [Getting Help](#getting-help)
  - [Debug Mode](#debug-mode)
  - [Error Information](#error-information)
  - [Community Support](#community-support)
<!-- TOC END -->

**Version**: 0.12.0-dev | **Updated**: April 14, 2026

Common issues and solutions for flext-auth authentication service.

For general FLEXT troubleshooting, see **[flext-core](https://github.com/organization/flext/tree/main/flext-core/README.md)** documentation.

______________________________________________________________________

## Authentication Issues

### User Registration Failures

**Problem**: User registration fails with validation errors

```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_admin_user=False)
result = auth.register_user("user", "invalid-email", "weak")
# Returns failure result
```

**Solutions**:

1. **Email Validation**:

   ```python
   from flext_auth import FlextAuth

   auth = FlextAuth.quick_start(create_admin_user=False)
   result = auth.register_user("user", "user@example.com", "password123")
   ```

1. **Password Requirements**:

   ```python
   from flext_auth import FlextAuth

   auth = FlextAuth.quick_start(create_admin_user=False)
   result = auth.register_user("user", "user@example.com", "SecurePassword123!")
   ```

1. **Username Uniqueness**:

   ```python
   from flext_auth import FlextAuth
   from flext_cli import u

   auth = FlextAuth.quick_start(create_admin_user=False)
   existing_user = auth.identity_service.user_manager.get_user_by_username("username")
   if existing_user.success:
       u.Cli.info("User already exists")
   ```

### Authentication Failures

**Problem**: User authentication fails unexpectedly

```python
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_admin_user=False)
auth.register_user("user", "user@example.com", "password123")
auth_result = auth.authenticate_user("user", "password123")
# Returns failure even with correct credentials
```

**Debugging**:

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)
auth.register_user("user", "user@example.com", "password123")

# Check if user exists
user_result = auth.identity_service.user_manager.get_user_by_username("user")
if user_result.failure:
    u.Cli.info("User not found")
else:
    user = user_result.unwrap()
    # Check password verification
    verify_result = user.verify_credential("password123")
    u.Cli.info(f"Password verification: {verify_result.success}")
```

**Common Causes**:

1. **Case sensitivity**: Usernames are case-sensitive
1. **Password hashing**: Ensure bcrypt is working correctly
1. **User state**: Check if user is active

### Token Validation Issues

**Problem**: JWT token validation fails

```python notest
from flext_auth import FlextAuth

auth = FlextAuth.quick_start(create_admin_user=False)
registered = auth.register_user("user", "user@example.com", "password123")
if registered.success:
    token_result = auth.create_token(registered.unwrap().unique_id)
    if token_result.success:
        token = token_result.unwrap()
        validation_result = auth.token_service.validate_token(token)
        # Returns failure for valid tokens
```

**Solutions**:

1. **Token Format**:

   ```python
   # Ensure proper Bearer format or clean token
   token = "Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
   # or
   token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
   ```

1. **Token Expiration**:

   ```python
   import jwt

   # Check token expiration without validation
   try:
       payload = jwt.decode(token, options={"verify_signature": False})
       u.Cli.print(f"Token expires at: {payload.get('exp')}")
   except jwt.InvalidTokenError as e:
       u.Cli.print(f"Token error: {e}")
   ```

1. **Secret Key Mismatch**:

   ```python
   # Ensure same secret key is used for generation and validation
   settings = FlextAuthSettings()
   u.Cli.print(f"JWT Secret: {settings.jwt_secret_key}")
   ```

______________________________________________________________________

## Configuration Issues

### Environment Configuration

**Problem**: Configuration not loading correctly

```python notest
from flext_auth import FlextAuthSettings

settings = FlextAuthSettings()
# Access namespaced auth settings via settings.Auth
u.Cli.info(f"JWT secret configured: {bool(settings.Auth.secret_key)}")
```

**Solutions**:

1. **Check Environment Variables**:

   ```bash
   env | grep FLEXT_AUTH_
   # Should show FLEXT_AUTH_* variables if set
   ```

1. **Valid Environment Names**:

   ```python notest
   # Use valid environment names
   valid_envs = ["development", "testing", "staging", "production"]
   settings = FlextAuthSettings()
   ```

1. **Manual Configuration**:

   ```python
   from flext_auth import FlextAuthSettings

   settings = FlextAuthSettings(Auth={"secret_key": "a" * 32, "expiry_minutes": 60})
   ```

### JWT Configuration

**Problem**: JWT tokens not working correctly

**Check Configuration**:

```python
from flext_auth import FlextAuthSettings
from flext_cli import u

settings = FlextAuthSettings()
u.Cli.info(f"JWT Algorithm: {settings.Auth.algorithm}")
u.Cli.info(f"JWT Expiry: {settings.Auth.expiry_minutes}")
u.Cli.info(f"Secret Key Length: {len(settings.Auth.secret_key)}")
```

**Recommendations**:

- Use HS256 algorithm (default)
- Secret key should be at least 32 characters
- Reasonable expiry time (15-60 minutes)

______________________________________________________________________

## Testing Issues

### Test Failures

**Problem**: Tests failing during development

**Current Status**: 66 out of 250 tests failing

**Common Failing Areas**:

1. **CLI Tests**:

   ```bash
   # Run CLI tests specifically
   pytest tests/unit/test_cli_coverage.py -v

   # Common issue: Missing test runner setup
   # Solution: Ensure proper test fixtures
   ```

1. **Configuration Tests**:

   ```bash
   # Run configuration tests
   pytest tests/unit/test_config_coverage.py -v

   # Common issue: Singleton state between tests
   # Solution: Reset global settings in test fixtures
   ```

1. **Mock Issues**:

   ```python
   import pytest

   from flext_auth import FlextAuth
   from flext_auth.services._auth_lifecycle import FlextAuthApplicationLifecycle


   @pytest.fixture(autouse=True)
   def reset_global_state():
       """Reset global state between tests."""
       FlextAuthApplicationLifecycle.reset_for_testing()
       yield
   ```

### Test Environment Setup

**Problem**: Tests fail due to environment setup

**Solution**:

```bash
# Ensure test environment is clean
uv sync --all-packages

# Run tests with proper environment
uv run pytest tests/ -v

# Run with coverage
uv run pytest --cov=src/flext_auth tests/
```

______________________________________________________________________

## Performance Issues

### Slow Authentication

**Problem**: Authentication operations are slow

**Investigation**:

```python
import time

from flext_auth import FlextAuth
from flext_auth import FlextAuthSettings
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)
registered = auth.register_user("bench", "bench@example.com", "password123")
identity = registered.unwrap()

# Measure bcrypt performance
start = time.time()
identity.update_credential("test_password")
bcrypt_time = time.time() - start
u.Cli.info(f"Bcrypt hashing took: {bcrypt_time:.3f}s")

# Check bcrypt rounds
settings = FlextAuthSettings()
u.Cli.info(f"Bcrypt rounds: {settings.Auth.hash_rounds}")
```

**Solutions**:

1. **Reduce bcrypt rounds for development**:

   ```python
   from flext_auth import FlextAuthSettings

   dev_config = FlextAuthSettings(Auth={"hash_rounds": 10})  # Faster for development
   ```

1. **Use production rounds only in production**:

   ```python
   from flext_auth import FlextAuthSettings

   prod_config = FlextAuthSettings(Auth={"hash_rounds": 14})  # High security
   ```

### Memory Usage

**Problem**: High memory usage with many sessions

**Current Limitation**: In-memory session storage

**Monitoring**:

```python notest
import psutil

from flext_auth import FlextAuth
from flext_cli import u

# Monitor memory usage
process = psutil.Process()
memory_mb = process.memory_info().rss / 1024 / 1024
u.Cli.info(f"Memory usage: {memory_mb:.1f} MB")

# Check session count
auth = FlextAuth.quick_start(create_admin_user=False)
session_count = len(
    auth.session_service.session_manager._sessions
)  # Internal attribute
u.Cli.info(f"Active sessions: {session_count}")
```

**Mitigation**:

```python notest
from __future__ import annotations


# Implement session cleanup
def cleanup_expired_sessions():
    """Clean up expired sessions (placeholder)."""
    # Implementation needed in FlextAuth service
    pass
```

______________________________________________________________________

## Development Issues

### IDE and Type Checking

**Problem**: Type checking errors with MyPy

**Common Issues**:

```bash
# Run type checking
uv run mypy src/flext_auth/

# Common errors:
# - Missing type annotations
# - r type issues
# - Generic type problems
```

**Solutions**:

1. **Type Annotations**:

   ```python notest
   from flext_auth import User, p


   def find_user(username: str) -> p.Result[User | None]:
       pass
   ```

1. **r Types**:

   ```python notest
   from flext_auth import FlextAuth, User, p

   auth = FlextAuth.quick_start(create_admin_user=False)
   # Specify generic type for r
   result: p.Result[User] = auth.register_user("user", "user@example.com", "password123")
   ```

### Import Issues

**Problem**: Circular imports or import errors

**Solution**:

```python notest
# Import via namespace alias (TYPE_CHECKING blocks are prohibited in models.py)
from flext_auth import m

# Access models via namespace
user = m.Auth.AuthIdentity(name="user", contact="user@example.com")
```

______________________________________________________________________

## Production Issues

### Security Concerns

**Problem**: Security vulnerabilities in production

**Security Checklist**:

```bash
# Check for security issues
uv run bandit -r src/flext_auth/

# Verify secure configuration
uv run python -c "
from flext_auth import FlextAuthSettings
from flext_cli import u

settings = FlextAuthSettings()
u.Cli.info(f'Bcrypt rounds: {settings.Auth.hash_rounds}')  # Should be >= 12
u.Cli.info(f'JWT expiry: {settings.Auth.expiry_minutes}')  # Should be <= 60
u.Cli.info(f'Max sessions per user: {settings.Auth.max_sessions_per_user}')  # Should be <= 5
"
```

### Session Management

**Problem**: Session issues in production

**Current Limitation**: In-memory sessions don't persist

**Workarounds**:

1. **Session timeout management**:

   ```python notest
   # Implement session cleanup
   def cleanup_sessions():
       """Clean expired sessions."""
       # Implementation needed
       pass
   ```

1. **External session storage** (future):

   ```python notest
   # Future Redis integration
   class RedisSessionStorage:
       def store_session(self, session):
           # Redis implementation
           pass
   ```

______________________________________________________________________

## Getting Help

### Debug Mode

Enable debug logging:

```python
import logging

from flext_auth import FlextAuth

# Enable debug logging
logging.basicConfig(level=logging.DEBUG)

# Test authentication with debug output
auth = FlextAuth.quick_start(create_admin_user=False)
result = auth.register_user("debug", "debug@example.com", "password123")
```

### Error Information

Extract detailed error information:

```python
from flext_auth import FlextAuth
from flext_cli import u

auth = FlextAuth.quick_start(create_admin_user=False)
result = auth.authenticate_user("user", "wrong_password")
if result.failure:
    u.Cli.info(f"Error: {result.error}")
    u.Cli.info(f"Error type: {type(result.error)}")
    # Additional debugging information
```

### Community Support

- **Documentation**: Check Getting Started and API Reference
- **Issues**: Report bugs in GitHub Issues
- **Security**: Report security issues privately to maintainers

______________________________________________________________________

This troubleshooting guide reflects common issues as of April 14, 2026. For additional help, see the Development guide.

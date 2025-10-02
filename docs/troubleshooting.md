# Troubleshooting

**Version**: 0.9.9 RC | **Updated**: September 17, 2025

Common issues and solutions for flext-auth authentication service.

For general FLEXT troubleshooting, see **[flext-core](../../flext-core/README.md)** documentation.

---

## Authentication Issues

### User Registration Failures

**Problem**: User registration fails with validation errors

```python
result = auth.register_user("user", "invalid-email", "weak")
# Returns failure result
```

**Solutions**:

1. **Email Validation**:

   ```python
   # Use valid email format
   result = auth.register_user("user", "user@example.com", "password123")
   ```

2. **Password Requirements**:

   ```python
   # Use stronger password (current implementation has basic validation)
   result = auth.register_user("user", "user@example.com", "SecurePassword123!")
   ```

3. **Username Uniqueness**:

   ```python
   # Check if user already exists
   existing_user = auth._find_user("username")  # Internal method
   if existing_user.is_success:
       print("User already exists")
   ```

### Authentication Failures

**Problem**: User authentication fails unexpectedly

```python
auth_result = auth.authenticate_user("user", "password")
# Returns failure even with correct credentials
```

**Debugging**:

```python
# Check if user exists
user_result = auth._find_user("user")
if user_result.is_failure:
    print("User not found")
else:
    user = user_result.unwrap()
    # Check password verification
    verify_result = user.verify_password("password")
    print(f"Password verification: {verify_result.is_success}")
```

**Common Causes**:

1. **Case sensitivity**: Usernames are case-sensitive
2. **Password hashing**: Ensure bcrypt is working correctly
3. **User state**: Check if user is active

### Token Validation Issues

**Problem**: JWT token validation fails

```python
validation_result = auth.validate_token(token)
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

2. **Token Expiration**:

   ```python
   import jwt

   # Check token expiration without validation
   try:
       payload = jwt.decode(token, options={"verify_signature": False})
       print(f"Token expires at: {payload.get('exp')}")
   except jwt.InvalidTokenError as e:
       print(f"Token error: {e}")
   ```

3. **Secret Key Mismatch**:

   ```python
   # Ensure same secret key is used for generation and validation
   config = FlextAuthConfig()
   print(f"JWT Secret: {config.jwt_secret_key}")
   ```

---

## Configuration Issues

### Environment Configuration

**Problem**: Configuration not loading correctly

```python
config = FlextAuthConfig.create_for_environment("production")
if config.is_failure:
    print(f"Config error: {config.error}")
```

**Solutions**:

1. **Check Environment Variables**:

   ```bash
   env | grep AUTH_
   # Should show AUTH_* variables if set
   ```

2. **Valid Environment Names**:

   ```python
   # Use valid environment names
   valid_envs = ["development", "testing", "staging", "production"]
   config = FlextAuthConfig.create_for_environment("development")
   ```

3. **Manual Configuration**:

   ```python
   # Create configuration manually if environment fails
   config = FlextAuthConfig(
       jwt_secret_key="manual-secret-key",
       jwt_expiry_minutes=60
   )
   ```

### JWT Configuration

**Problem**: JWT tokens not working correctly

**Check Configuration**:

```python
config = FlextAuthConfig()
print(f"JWT Algorithm: {config.jwt_algorithm}")
print(f"JWT Expiry: {config.jwt_expiry_minutes}")
print(f"Secret Key Length: {len(config.jwt_secret_key)}")
```

**Recommendations**:

- Use HS256 algorithm (default)
- Secret key should be at least 32 characters
- Reasonable expiry time (15-60 minutes)

---

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

2. **Configuration Tests**:

   ```bash
   # Run configuration tests
   pytest tests/unit/test_config_coverage.py -v

   # Common issue: Singleton state between tests
   # Solution: Reset global config in test fixtures
   ```

3. **Mock Issues**:

   ```python
   # In test fixtures
   @pytest.fixture(autouse=True)
   def reset_global_state():
       """Reset global state between tests."""
       FlextAuthConfig._global_instance = None
       yield
   ```

### Test Environment Setup

**Problem**: Tests fail due to environment setup

**Solution**:

```bash
# Ensure test environment is clean
poetry install --with test

# Run tests with proper environment
PYTHONPATH=src pytest tests/ -v

# Run with coverage
pytest --cov=src/flext_auth tests/
```

---

## Performance Issues

### Slow Authentication

**Problem**: Authentication operations are slow

**Investigation**:

```python
import time

# Measure bcrypt performance
start = time.time()
user.set_password("test_password")
bcrypt_time = time.time() - start
print(f"Bcrypt hashing took: {bcrypt_time:.3f}s")

# Check bcrypt rounds
config = FlextAuthConfig()
print(f"Bcrypt rounds: {config.bcrypt_rounds}")
```

**Solutions**:

1. **Reduce bcrypt rounds for development**:

   ```python
   dev_config = FlextAuthConfig(bcrypt_rounds=10)  # Faster for development
   ```

2. **Use production rounds only in production**:

   ```python
   prod_config = FlextAuthConfig(bcrypt_rounds=14)  # High security
   ```

### Memory Usage

**Problem**: High memory usage with many sessions

**Current Limitation**: In-memory session storage

**Monitoring**:

```python
import psutil

# Monitor memory usage
process = psutil.Process()
memory_mb = process.memory_info().rss / 1024 / 1024
print(f"Memory usage: {memory_mb:.1f} MB")

# Check session count
auth = FlextAuth()
session_count = len(auth._sessions)  # Internal attribute
print(f"Active sessions: {session_count}")
```

**Mitigation**:

```python
# Implement session cleanup
def cleanup_expired_sessions():
    """Clean up expired sessions (placeholder)."""
    # Implementation needed in FlextAuth service
    pass
```

---

## Development Issues

### IDE and Type Checking

**Problem**: Type checking errors with MyPy

**Common Issues**:

```bash
# Run type checking
mypy src/flext_auth/

# Common errors:
# - Missing type annotations
# - FlextResult type issues
# - Generic type problems
```

**Solutions**:

1. **Type Annotations**:

   ```python
   # Always use proper type hints
   from typing import Optional

   def find_user(username: str) -> FlextResult[Optional[User]]:
       pass
   ```

2. **FlextResult Types**:

   ```python
   # Specify generic type for FlextResult
   result: FlextResult[User] = auth.register_user(...)
   ```

### Import Issues

**Problem**: Circular imports or import errors

**Solution**:

```python
# Use late imports if needed
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_auth.models import User

# Or restructure imports to avoid cycles
```

---

## Production Issues

### Security Concerns

**Problem**: Security vulnerabilities in production

**Security Checklist**:

```bash
# Check for security issues
bandit -r src/flext_auth/

# Verify secure configuration
python -c "
from flext_auth import FlextAuthConfig
config = FlextAuthConfig.create_for_environment('production').unwrap()
print(f'Bcrypt rounds: {config.bcrypt_rounds}')  # Should be >= 12
print(f'JWT expiry: {config.jwt_expiry_minutes}')  # Should be <= 60
print(f'Max attempts: {config.max_failed_attempts}')  # Should be <= 5
"
```

### Session Management

**Problem**: Session issues in production

**Current Limitation**: In-memory sessions don't persist

**Workarounds**:

1. **Session timeout management**:

   ```python
   # Implement session cleanup
   def cleanup_sessions():
       """Clean expired sessions."""
       # Implementation needed
       pass
   ```

2. **External session storage** (future):

   ```python
   # Future Redis integration
   class RedisSessionStorage:
       def store_session(self, session):
           # Redis implementation
           pass
   ```

---

## Getting Help

### Debug Mode

Enable debug logging:

```python

logging.basicConfig(level=logging.DEBUG)

# Test authentication with debug output
auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
result = auth.register_user("debug", "debug@example.com", "password123")
```

### Error Information

Extract detailed error information:

```python
result = auth.authenticate_user("user", "wrong_password")
if result.is_failure:
    print(f"Error: {result.error}")
    print(f"Error type: {type(result.error)}")
    # Additional debugging information
```

### Community Support

- **Documentation**: Check [Getting Started](getting-started.md) and [API Reference](api-reference.md)
- **Issues**: Report bugs in GitHub Issues
- **Security**: Report security issues privately to maintainers

---

This troubleshooting guide reflects common issues as of September 17, 2025. For additional help, see the [Development](development.md) guide.

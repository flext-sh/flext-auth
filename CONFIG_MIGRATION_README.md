# FLEXT Auth Configuration Migration Guide

This guide provides step-by-step instructions for migrating flext-auth to use the centralized configuration system from flext-core.

## Overview

The migration replaces hardcoded configuration values with a centralized, type-safe configuration system based on Pydantic and pydantic-settings. This provides:

- ✅ **Type safety** with full IDE support
- ✅ **Environment variable support** with FLEXT*AUTH* prefix
- ✅ **Validation** of configuration values
- ✅ **Documentation** of all settings
- ✅ **Easy testing** with environment variable overrides

## Quick Start

### 1. New Configuration Module

The new configuration is available at:

```python
from flext_auth.config import settings

# Access configuration
print(settings.jwt_algorithm)  # "HS256"
print(settings.session_timeout_hours)  # 24
```

### 2. Environment Variables

All settings can be overridden via environment variables:

```bash
# JWT Settings
export FLEXT_AUTH_JWT_ALGORITHM=RS256
export FLEXT_AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=60
export FLEXT_AUTH_JWT_SECRET_KEY=your-secret-key-here

# Session Settings
export FLEXT_AUTH_SESSION_TIMEOUT_HOURS=48
export FLEXT_AUTH_MAX_SESSIONS_PER_USER=3

# Password Settings
export FLEXT_AUTH_PASSWORD_MIN_LENGTH=12
export FLEXT_AUTH_PASSWORD_REQUIRE_SPECIAL=true
```

### 3. Configuration File (.env)

Create a `.env` file in your project root:

```env
# FLEXT Auth Configuration
FLEXT_AUTH_PROJECT_NAME=my-auth-service
FLEXT_AUTH_ENVIRONMENT=production
FLEXT_AUTH_DEBUG=false

# JWT Configuration
FLEXT_AUTH_JWT_ALGORITHM=HS256
FLEXT_AUTH_JWT_SECRET_KEY=your-production-secret-key
FLEXT_AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES=30
FLEXT_AUTH_JWT_REFRESH_TOKEN_EXPIRE_DAYS=7

# Redis Configuration (optional)
FLEXT_AUTH_REDIS_URL=redis://localhost:6379/0
FLEXT_AUTH_REDIS_POOL_SIZE=20
```

## Migration Steps

### Step 1: Update jwt_service.py

Replace the hardcoded `_get_jwt_config()` function:

```python
# Add import
from flext_auth.config import settings

# Replace the function (lines 26-35)
def _get_jwt_config() -> JWTConfig:
    """Get JWT configuration from centralized settings."""
    return JWTConfig(
        algorithm=settings.jwt_algorithm,
        access_token_expire_minutes=settings.jwt_access_token_expire_minutes,
        refresh_token_expire_days=settings.jwt_refresh_token_expire_days,
        issuer=settings.jwt_issuer,
        audience=settings.jwt_audience,
        secret_key=settings.jwt_secret_key.get_secret_value(),
        public_key=settings.jwt_public_key,
        private_key=(
            settings.jwt_private_key.get_secret_value()
            if settings.jwt_private_key else None
        ),
        leeway_seconds=settings.jwt_leeway_seconds,
        verify_signature=True,
        verify_exp=True,
        verify_aud=True,
        require_exp=True,
    )
```

### Step 2: Update session_manager.py

Remove hardcoded configuration loading and use settings:

```python
# Add import
from flext_auth.config import settings

# In EnterpriseSessionManager.__init__, remove:
# self.config = get_config()
# self.constants = get_domain_constants()

# Update session duration usage:
if not session_duration:
    session_duration = settings.session_timeout_timedelta
```

### Step 3: Update password hashing

If you have password configuration, update to use settings:

```python
from flext_auth.config import settings

# Use configured bcrypt rounds
hashed = bcrypt.hashpw(
    password.encode('utf-8'),
    bcrypt.gensalt(rounds=settings.bcrypt_rounds)
)

# Validate password requirements
if len(password) < settings.password_min_length:
    raise ValueError(f"Password must be at least {settings.password_min_length} characters")
```

## Available Settings

### JWT Configuration

- `jwt_algorithm`: JWT signing algorithm (HS256, RS256)
- `jwt_secret_key`: Secret key for HMAC-based JWT signing
- `jwt_access_token_expire_minutes`: Access token expiration (1-1440)
- `jwt_refresh_token_expire_days`: Refresh token expiration (1-90)
- `jwt_issuer`: JWT issuer identification
- `jwt_audience`: JWT audience specification
- `jwt_leeway_seconds`: Clock skew tolerance (0-300)
- `jwt_public_key`: RSA public key (RS256 only)
- `jwt_private_key`: RSA private key (RS256 only)

### Session Configuration

- `session_timeout_hours`: Default session timeout (1-168)
- `session_cleanup_interval_minutes`: Cleanup interval (5-1440)
- `max_sessions_per_user`: Max concurrent sessions (1-20)

### Password Configuration

- `bcrypt_rounds`: Bcrypt hashing rounds (10-16)
- `password_min_length`: Minimum length (6-128)
- `password_require_uppercase`: Require uppercase letters
- `password_require_lowercase`: Require lowercase letters
- `password_require_digits`: Require digits
- `password_require_special`: Require special characters

### Redis Configuration (Optional)

- `redis_url`: Redis connection URL
- `redis_ssl`: Enable SSL for Redis
- `redis_pool_size`: Connection pool size (1-100)

### RBAC Configuration

- `enable_rbac`: Enable role-based access control
- `default_user_role`: Default role for new users
- `super_REDACTED_LDAP_BIND_PASSWORD_email`: Email for initial super REDACTED_LDAP_BIND_PASSWORD

## Testing with Configuration

```python
import os
import pytest
from flext_auth.config import AuthSettings

def test_jwt_configuration(monkeypatch):
    """Test JWT configuration with environment overrides."""
    # Set test environment
    monkeypatch.setenv("FLEXT_AUTH_JWT_ALGORITHM", "RS256")
    monkeypatch.setenv("FLEXT_AUTH_JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "5")

    # Create settings
    settings = AuthSettings()

    # Verify
    assert settings.jwt_algorithm == "RS256"
    assert settings.jwt_access_token_expire_minutes == 5
    assert settings.jwt_access_token_expire_timedelta.total_seconds() == 300
```

## Backward Compatibility

To maintain backward compatibility during migration:

```python
from flext_auth.config import settings

# Create old-style config dict
jwt_config = {
    "algorithm": settings.jwt_algorithm,
    "secret_key": settings.jwt_secret_key.get_secret_value(),
    "access_token_expire_minutes": settings.jwt_access_token_expire_minutes,
    # ... other fields
}

# Or use the helper method
jwt_config = settings.get_jwt_config_dict()
```

## Benefits

1. **Centralized Configuration**: All settings in one place
2. **Type Safety**: Full IDE support and runtime validation
3. **Environment Support**: Easy deployment configuration
4. **Documentation**: All settings are documented
5. **Validation**: Automatic validation of values
6. **Testing**: Easy to override in tests

## Troubleshooting

### Settings not loading from environment

- Check the prefix: `FLEXT_AUTH_`
- Ensure variable names are uppercase: `FLEXT_AUTH_JWT_ALGORITHM`
- For nested settings use double underscore: `FLEXT_AUTH_REDIS__HOST`

### Validation errors

- Check the validation rules (e.g., jwt_algorithm must be HS256 or RS256)
- Ensure required fields have values
- Check min/max constraints on numeric fields

### Import errors

- Ensure flext-core >= 0.6.0 is installed
- The config module is at: `flext_auth.config`

## Next Steps

1. Review all hardcoded configuration values in your code
2. Add them to the `AuthSettings` class if missing
3. Update code to use `settings` instead of hardcoded values
4. Create a `.env` file for your deployment
5. Test with different configurations

For more examples, see the `examples/` directory:

- `config_migration.py`: Complete migration example
- `jwt_service_migration.py`: JWT service migration
- `session_manager_migration.py`: Session manager migration

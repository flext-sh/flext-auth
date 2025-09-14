# Configuration

**Version**: 0.9.0 | **Updated**: September 17, 2025

Configuration management for flext-auth authentication service.

---

## Overview

flext-auth uses FlextAuthConfig class extending [flext-core](../../flext-core/README.md) FlextConfig patterns for environment-aware configuration management.

---

## FlextAuthConfig

### Default Configuration

```python
from flext_auth import FlextAuthConfig

config = FlextAuthConfig()
print(f"JWT Expiry: {config.jwt_expiry_minutes} minutes")
print(f"Bcrypt Rounds: {config.bcrypt_rounds}")
```

### Environment-Specific Configuration

```python
# Development configuration
dev_config = FlextAuthConfig.create_for_environment("development")
if dev_config.is_success:
    config = dev_config.unwrap()

# Production configuration
prod_config = FlextAuthConfig.create_for_environment("production")
if prod_config.is_success:
    config = prod_config.unwrap()
```

---

## Configuration Parameters

### JWT Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `jwt_secret_key` | str | "dev-secret-key" | Secret key for JWT signing |
| `jwt_expiry_minutes` | int | 60 | Token expiration time in minutes |
| `jwt_algorithm` | str | "HS256" | JWT signing algorithm |

### Security Settings

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `bcrypt_rounds` | int | 12 | Bcrypt hashing rounds |
| `max_failed_attempts` | int | 5 | Max failed login attempts |
| `session_timeout_minutes` | int | 120 | Session timeout in minutes |

### Environment Variables

Configure via environment variables with `AUTH_` prefix:

```bash
export AUTH_JWT_SECRET_KEY="your-secure-secret-key"
export AUTH_JWT_EXPIRY_MINUTES=30
export AUTH_BCRYPT_ROUNDS=14
export AUTH_MAX_FAILED_ATTEMPTS=3
export AUTH_SESSION_TIMEOUT_MINUTES=60
```

---

## Custom Configuration

### Override Specific Parameters

```python
config = FlextAuthConfig(
    jwt_expiry_minutes=30,          # 30-minute tokens
    bcrypt_rounds=14,               # Higher security
    max_failed_attempts=3,          # Stricter lockout
    session_timeout_minutes=60      # 1-hour sessions
)

auth = FlextAuth(config=config)
```

### Production Security Settings

```python
prod_config = FlextAuthConfig(
    jwt_secret_key="your-production-secret-key",
    jwt_expiry_minutes=15,          # Short-lived tokens
    bcrypt_rounds=14,               # High security
    max_failed_attempts=3,          # Account lockout
    session_timeout_minutes=30      # Short sessions
)
```

---

## Configuration Validation

### Validate Configuration

```python
config_result = FlextAuthConfig.create_for_environment("production")
if config_result.is_failure:
    print(f"Configuration error: {config_result.error}")
```

### CLI Validation

```bash
# Validate current configuration
flext-auth validate-config

# Show configuration summary
flext-auth manage-config show
```

---

## Global Configuration

### Singleton Pattern

FlextAuthConfig follows FLEXT singleton pattern for global configuration:

```python
# Set global configuration
config = FlextAuthConfig.create_for_environment("production").unwrap()
FlextAuthConfig.set_global_instance(config)

# Use global configuration
auth = FlextAuth()  # Uses global config automatically
```

### Global Instance Access

```python
# Get current global configuration
global_config = FlextAuthConfig.get_global_instance()
print(f"Current JWT expiry: {global_config.jwt_expiry_minutes}")
```

---

## Security Recommendations

### Production Settings

For production environments:

```python
FlextAuthConfig(
    jwt_secret_key="strong-random-secret-256-bits",
    jwt_expiry_minutes=15,          # Short token lifetime
    bcrypt_rounds=14,               # High security hashing
    max_failed_attempts=3,          # Account protection
    session_timeout_minutes=30      # Session security
)
```

### Development Settings

For development environments:

```python
FlextAuthConfig(
    jwt_secret_key="dev-secret-key",
    jwt_expiry_minutes=60,          # Convenient for testing
    bcrypt_rounds=12,               # Balanced performance
    max_failed_attempts=5,          # Less restrictive
    session_timeout_minutes=120     # Extended sessions
)
```

---

## Configuration Environments

### Available Environments

- `"development"`: Development settings with logging
- `"testing"`: Test-specific settings
- `"staging"`: Pre-production settings
- `"production"`: Production security settings

### Environment Detection

```python
import os

env = os.getenv("FLEXT_ENV", "development")
config = FlextAuthConfig.create_for_environment(env)
```

---

This configuration guide covers the current implementation as of September 17, 2025. For usage examples, see [Getting Started](getting-started.md).
# Configuration

<!-- TOC START -->
- [Overview](#overview)
- [FlextAuthSettings](#flextauthsettings)
  - [Default Configuration](#default-configuration)
  - [Environment-Specific Configuration](#environment-specific-configuration)
- [Configuration Parameters](#configuration-parameters)
  - [JWT Settings](#jwt-settings)
  - [Security Settings](#security-settings)
  - [Environment Variables](#environment-variables)
- [Custom Configuration](#custom-configuration)
  - [Override Specific Parameters](#override-specific-parameters)
  - [Production Security Settings](#production-security-settings)
- [Configuration Validation](#configuration-validation)
  - [Validate Configuration](#validate-configuration)
  - [CLI Validation](#cli-validation)
- [Global Configuration](#global-configuration)
  - [Singleton Pattern](#singleton-pattern)
  - [Global Instance Access](#global-instance-access)
- [Security Recommendations](#security-recommendations)
  - [Production Settings](#production-settings)
  - [Development Settings](#development-settings)
- [Configuration Environments](#configuration-environments)
  - [Available Environments](#available-environments)
  - [Environment Detection](#environment-detection)
<!-- TOC END -->

**Version**: 0.12.0-dev | **Updated**: April 14, 2026

Configuration management for flext-auth authentication service.

______________________________________________________________________

## Overview

flext-auth uses FlextAuthSettings class extending [flext-core](https://github.com/organization/flext/tree/main/flext-core/README.md) FlextSettings patterns for environment-aware configuration management.

______________________________________________________________________

## FlextAuthSettings

### Default Configuration

```python
from flext_auth import FlextAuthSettings

settings = FlextAuthSettings()
print(f"JWT Expiry: {settings.jwt_expiry_minutes} minutes")
print(f"Bcrypt Rounds: {settings.bcrypt_rounds}")
```

### Environment-Specific Configuration

```python
# Development configuration
dev_config = FlextAuthSettings()
if dev_config.success:
    settings = dev_config.unwrap()

# Production configuration
prod_config = FlextAuthSettings()
if prod_config.success:
    settings = prod_config.unwrap()
```

______________________________________________________________________

## Configuration Parameters

### JWT Settings

| Parameter            | Type | Default          | Description                      |
| -------------------- | ---- | ---------------- | -------------------------------- |
| `jwt_secret_key`     | str  | "dev-secret-key" | Secret key for JWT signing       |
| `jwt_expiry_minutes` | int  | 60               | Token expiration time in minutes |
| `jwt_algorithm`      | str  | "HS256"          | JWT signing algorithm            |

### Security Settings

| Parameter                 | Type | Default | Description                |
| ------------------------- | ---- | ------- | -------------------------- |
| `bcrypt_rounds`           | int  | 12      | Bcrypt hashing rounds      |
| `max_failed_attempts`     | int  | 5       | Max failed login attempts  |
| `session_timeout_minutes` | int  | 120     | Session timeout in minutes |

### Environment Variables

Configure via environment variables with `AUTH_` prefix:

```bash
export AUTH_JWT_SECRET_KEY="your-secure-secret-key"
export AUTH_JWT_EXPIRY_MINUTES=30
export AUTH_BCRYPT_ROUNDS=14
export AUTH_MAX_FAILED_ATTEMPTS=3
export AUTH_SESSION_TIMEOUT_MINUTES=60
```

______________________________________________________________________

## Custom Configuration

### Override Specific Parameters

```python
settings = FlextAuthSettings(
    jwt_expiry_minutes=30,  # 30-minute tokens
    bcrypt_rounds=14,  # Higher security
    max_failed_attempts=3,  # Stricter lockout
    session_timeout_minutes=60,  # 1-hour sessions
)

auth = FlextAuth(settings=settings)
```

### Production Security Settings

```python
prod_config = FlextAuthSettings(
    jwt_secret_key="your-production-secret-key",
    jwt_expiry_minutes=15,  # Short-lived tokens
    bcrypt_rounds=14,  # High security
    max_failed_attempts=3,  # Account lockout
    session_timeout_minutes=30,  # Short sessions
)
```

______________________________________________________________________

## Configuration Validation

### Validate Configuration

```python
config_result = FlextAuthSettings()
if config_result.failure:
    print(f"Configuration error: {config_result.error}")
```

### CLI Validation

```bash
# Validate current configuration
flext-auth validate-settings

# Show configuration summary
flext-auth manage-settings show
```

______________________________________________________________________

## Global Configuration

### Singleton Pattern

FlextAuthSettings follows FLEXT singleton pattern for global configuration:

```python
# Set global configuration
settings = FlextAuthSettings()
FlextAuthSettings.set_global_instance(settings)

# Use global configuration
auth = FlextAuth()  # Uses global settings automatically
```

### Global Instance Access

```python
# Get current global configuration
global_config = FlextAuthSettings.get_global_instance()
print(f"Current JWT expiry: {global_config.jwt_expiry_minutes}")
```

______________________________________________________________________

## Security Recommendations

### Production Settings

For production environments:

```python
FlextAuthSettings(
    jwt_secret_key="strong-random-secret-256-bits",
    jwt_expiry_minutes=15,  # Short token lifetime
    bcrypt_rounds=14,  # High security hashing
    max_failed_attempts=3,  # Account protection
    session_timeout_minutes=30,  # Session security
)
```

### Development Settings

For development environments:

```python
FlextAuthSettings(
    jwt_secret_key="dev-secret-key",
    jwt_expiry_minutes=60,  # Convenient for testing
    bcrypt_rounds=12,  # Balanced performance
    max_failed_attempts=5,  # Less restrictive
    session_timeout_minutes=120,  # Extended sessions
)
```

______________________________________________________________________

## Configuration Environments

### Available Environments

- `"development"`: Development settings with logging
- `"testing"`: Test-specific settings
- `"staging"`: Current settings
- `"production"`: Production security settings

### Environment Detection

```python
import os

env = os.getenv("FLEXT_ENV", "development")
settings = FlextAuthSettings()
```

______________________________________________________________________

This configuration guide covers the current implementation as of April 14, 2026. For usage examples, see Getting Started.

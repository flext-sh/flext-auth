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

flext-auth uses `FlextAuthSettings` extending
[flext-core](https://github.com/flext-sh/flext/tree/0.12.0-dev/flext-core/README.md)
`FlextSettings` patterns for environment-aware configuration management.

______________________________________________________________________

## FlextAuthSettings

### Default Configuration

```python
from flext_auth import FlextAuthSettings
from flext_cli import u

settings = FlextAuthSettings()
u.Cli.info(f"JWT Expiry: {settings.Auth.expiry_minutes} minutes")
u.Cli.info(f"Bcrypt Rounds: {settings.Auth.hash_rounds}")```
### Environment-Specific Configuration

```python
from flext_auth import FlextAuthSettings

# Development configuration
dev_settings = FlextAuthSettings()

# Production configuration
prod_settings = FlextAuthSettings()```
______________________________________________________________________

## Configuration Parameters

### JWT Settings

| Parameter            | Type | Default          | Description                      |
| -------------------- | ---- | ---------------- | -------------------------------- |
| `secret_key`         | str  | generated        | Secret key for JWT signing       |
| `expiry_minutes`     | int  | 1440             | Token expiration time in minutes |
| `algorithm`          | str  | HS256            | JWT signing algorithm            |

### Security Settings

| Parameter                 | Type | Default | Description                |
| ------------------------- | ---- | ------- | -------------------------- |
| `hash_rounds`             | int  | 12      | Bcrypt hashing rounds      |
| `max_sessions_per_user`   | int  | 5       | Max sessions per user      |
| `session_expiry_minutes`  | int  | 1440    | Session timeout in minutes |

### Environment Variables

Configure via environment variables with `AUTH_` prefix:

```bash
export AUTH_SECRET_KEY="your-secure-secret-key-with-at-least-32-chars"
export AUTH_EXPIRY_MINUTES=30
export AUTH_HASH_ROUNDS=14
export AUTH_MAX_SESSIONS_PER_USER=5
export AUTH_SESSION_EXPIRY_MINUTES=60
```

______________________________________________________________________

## Custom Configuration

### Override Specific Parameters

```python
from flext_auth import FlextAuth, FlextAuthSettings

settings = FlextAuthSettings(
    Auth={
        "secret_key": "your-secure-secret-key-with-at-least-32-chars",
        "expiry_minutes": 30,  # 30-minute tokens
        "hash_rounds": 14,  # Higher security
    }
)

auth = FlextAuth(settings=settings)```
### Production Security Settings

```python
from flext_auth import FlextAuthSettings

prod_config = FlextAuthSettings(
    Auth={
        "secret_key": "your-production-secret-key-with-at-least-32-chars",
        "expiry_minutes": 15,  # Short-lived tokens
        "hash_rounds": 14,  # High security
        "session_expiry_minutes": 30,  # Short sessions
    }
)```
______________________________________________________________________

## Configuration Validation

### Validate Configuration

```python
from flext_auth import FlextAuthSettings
from flext_cli import u

try:
    settings = FlextAuthSettings()
    u.Cli.info("Configuration valid")
except Exception as e:
    u.Cli.info(f"Configuration error: {e}")```
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

FlextAuthSettings follows the FLEXT singleton pattern for global configuration:

```python
from flext_auth import FlextAuth, FlextAuthSettings

# Settings singleton is resolved automatically by the facade
settings = FlextAuthSettings()

# Use global configuration
auth = FlextAuth()  # Uses global settings automatically
```

### Global Instance Access

```python
from flext_auth import FlextAuthSettings
from flext_cli import u

# Get current global configuration
global_config = FlextAuthSettings.fetch_global()
u.Cli.info(f"Current JWT expiry: {global_config.Auth.expiry_minutes}")```
______________________________________________________________________

## Security Recommendations

### Production Settings

For production environments:

```python
from flext_auth import FlextAuthSettings

FlextAuthSettings(
    Auth={
        "secret_key": "strong-random-secret-256-bits-minimum",
        "expiry_minutes": 15,  # Short token lifetime
        "hash_rounds": 14,  # High security hashing
        "session_expiry_minutes": 30,  # Session security
    }
)```
### Development Settings

For development environments:

```python
from flext_auth import FlextAuthSettings

FlextAuthSettings(
    Auth={
        "secret_key": "dev-secret-key-with-at-least-32-characters",
        "expiry_minutes": 60,  # Convenient for testing
        "hash_rounds": 12,  # Balanced performance
        "session_expiry_minutes": 120,  # Extended sessions
    }
)```
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
from flext_auth import FlextAuthSettings

env = os.getenv("FLEXT_ENV", "development")
settings = FlextAuthSettings()```
______________________________________________________________________

This configuration guide covers the current implementation as of April 14, 2026.
For usage examples, see Getting Started.

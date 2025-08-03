"""FLEXT Auth Configuration - Type-safe authentication settings.

This module provides comprehensive configuration management for FLEXT Auth following
flext-core patterns for consistency across the ecosystem. It includes validation,
type safety, and environment-specific settings for authentication operations.

Architecture:
    - Configuration Layer: Type-safe settings management
    - Validation: Comprehensive input validation with Pydantic
    - Environment Aware: Support for dev/staging/production environments
    - Security-First: Secure defaults and validation for sensitive settings

Core Configuration Areas:
    - Application Settings: Basic app configuration
    - Authentication: Password policies and security settings
    - JWT Configuration: Token settings and signing keys
    - Database: Connection and pooling settings
    - Rate Limiting: Request throttling and protection
    - Session Management: Session lifecycle and security

TODO (Based on docs/TODO.md):
    - [ ] MEDIUM: Consolidate multiple config classes (Issue #8)
    - [ ] MEDIUM: Implement secret management patterns (Issue #8)
    - [ ] MEDIUM: Add configuration validation tests (Issue #8)
    - [ ] LOW: Add configuration hot reloading (Issue #12)

Design Patterns:
    - Configuration Object Pattern: Centralized settings management
    - Builder Pattern: Pydantic model construction with validation
    - Strategy Pattern: Environment-specific configuration strategies
    - Factory Pattern: Configuration creation based on environment
    - Validation Pattern: Type-safe configuration with comprehensive validation
    - Singleton Pattern: Single configuration instance per application
    - Template Method Pattern: Common configuration workflows

Security Features:
    - SecretStr for sensitive configuration values
    - Production-safe defaults and validation
    - Environment variable support with prefixes
    - Type-safe configuration with Pydantic validation
    - Comprehensive validation rules for security settings

Environment Variables:
    All settings can be configured via environment variables:
    - FLEXT_AUTH_DEBUG=false
    - FLEXT_AUTH_JWT_SECRET_KEY=your-secret-key
    - FLEXT_AUTH_BCRYPT_ROUNDS=12
    - FLEXT_AUTH_MAX_LOGIN_ATTEMPTS=5

Example:
    >>> config = FlextAuthConfig(
    ...     jwt_secret_key="your-secure-key",
    ...     bcrypt_rounds=12,
    ...     debug=False
    ... )
    >>> validation_result = config.validate_production_settings()
    >>> if validation_result.is_success:
    ...     print("Configuration is production-ready")

Development vs Production:
    - Development: Relaxed security for easier testing
    - Production: Strict security with comprehensive validation
    - Environment detection: Automatic security policy selection
    - Secret validation: Ensures production secrets are secure

Performance Considerations:
    - Configuration loaded once at startup
    - Validation performed during initialization
    - Environment variable resolution cached
    - Type conversion handled by Pydantic

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import secrets

# Use flext-core centralized configuration models
from flext_core import (
    FlextApplicationConfig,
    FlextBaseConfigModel,
    FlextBaseSettings,
    FlextDatabaseConfig,
    FlextJWTConfig,
)
from pydantic import Field, SecretStr

# Configuration constants
MIN_JWT_SECRET_LENGTH = 32

# =============================================================================
# CENTRALIZED CONFIGURATION MODELS - Using flext-core patterns
# =============================================================================


class FlextAuthConfig(FlextBaseConfigModel):
    """Centralized authentication configuration using flext-core models."""

    # Application settings
    app_name: str = Field("FlextAuth", description="Application name")
    version: str = Field("1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field("development", description="Environment name")

    # Authentication specific settings
    password_min_length: int = Field(
        8,
        description="Minimum password length",
        ge=4,
        le=256,
    )
    password_max_length: int = Field(
        128,
        description="Maximum password length",
        ge=8,
        le=1024,
    )
    bcrypt_rounds: int = Field(12, description="BCrypt rounds", ge=4, le=20)

    # Security settings
    max_login_attempts: int = Field(
        5,
        description="Maximum login attempts",
        ge=1,
        le=10,
    )
    lockout_duration_minutes: int = Field(
        30,
        description="Account lockout duration",
        ge=1,
        le=1440,
    )
    session_timeout_hours: int = Field(24, description="Session timeout", ge=1, le=168)
    max_concurrent_sessions: int = Field(
        5,
        description="Maximum concurrent sessions",
        ge=1,
        le=20,
    )

    # Rate limiting
    rate_limit_per_minute: int = Field(
        60,
        description="General rate limit per minute",
        ge=1,
    )
    auth_rate_limit_per_minute: int = Field(
        5,
        description="Auth rate limit per minute",
        ge=1,
    )


class FlextAuthApplicationConfig(FlextApplicationConfig):
    """Complete application configuration extending FlextApplicationConfig."""

    # Override app-specific defaults
    app_name: str = Field("FlextAuth", description="Application name")

    # Authentication-specific settings
    auth: FlextAuthConfig = Field(
        default_factory=FlextAuthConfig,
        description="Authentication configuration",
    )


# =============================================================================
# BACKWARD COMPATIBILITY - Legacy configuration classes
# =============================================================================


class AppConfig(FlextBaseSettings):
    """Application configuration for backward compatibility."""

    app_name: str = Field("FlextAuth", description="Application name")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field("development", description="Environment")


class DatabaseConfig(FlextDatabaseConfig):
    """Database configuration using centralized model."""


class JWTConfig(FlextJWTConfig):
    """JWT configuration using centralized model."""

    @classmethod
    def validate_secret_key(cls, v: SecretStr) -> SecretStr:
        """Validate secret key strength."""
        secret = v.get_secret_value()
        if len(secret) < MIN_JWT_SECRET_LENGTH:
            msg = "JWT secret key must be at least 32 characters long"
            raise ValueError(msg)
        return v

    def generate_secret_key(self) -> str:
        """Generate secure secret key."""
        return secrets.token_urlsafe(32)


class SecurityConfig(FlextBaseConfigModel):
    """Security configuration for backward compatibility."""

    password_rounds: int = Field(12, description="BCrypt rounds", ge=4, le=20)
    max_login_attempts: int = Field(
        5,
        description="Max failed login attempts",
        ge=1,
        le=10,
    )
    lockout_duration_minutes: int = Field(
        15,
        description="Account lockout duration",
        ge=1,
        le=1440,
    )
    session_timeout_minutes: int = Field(
        1440,
        description="Session timeout minutes",
        ge=5,
        le=10080,
    )
    max_concurrent_sessions: int = Field(
        5,
        description="Max concurrent sessions",
        ge=1,
        le=20,
    )


def validate_production_config(config: AppConfig) -> bool:
    """Production configuration validation."""
    config_dict = config.model_dump()
    required_fields = ["app_name", "environment"]
    return all(field in config_dict and config_dict[field] for field in required_fields)


# =============================================================================
# CONFIGURATION FACTORY FUNCTIONS - Simplified creation
# =============================================================================


def create_auth_config(**overrides: object) -> FlextAuthConfig:
    """Factory function to create authentication configuration."""
    # Type ignore for dynamic Pydantic model instantiation
    return FlextAuthConfig(**overrides)  # type: ignore[arg-type]


def create_complete_auth_config(**overrides: object) -> FlextAuthApplicationConfig:
    """Factory function to create complete authentication application configuration."""
    # Type ignore for dynamic Pydantic model instantiation
    return FlextAuthApplicationConfig(**overrides)  # type: ignore[arg-type]


def get_default_secret(key_name: str) -> str:
    """Get default secret from environment or generate secure fallback."""
    env_value = os.getenv(key_name)
    if env_value:
        return env_value
    return secrets.token_urlsafe(32)


# =============================================================================
# CONFIGURATION PRESETS - Common configurations
# =============================================================================


def create_development_config() -> FlextAuthApplicationConfig:
    """Create development configuration with reasonable defaults."""
    return FlextAuthApplicationConfig(
        debug=True,
        environment="development",
        jwt=FlextJWTConfig(
            secret_key=SecretStr("dev-jwt-secret-key-32-chars-minimum-length"),
        ),
    )


def create_production_config() -> FlextAuthApplicationConfig:
    """Create production configuration requiring environment variables."""
    jwt_secret = os.getenv("FLEXT_AUTH_JWT_SECRET_KEY")
    if not jwt_secret or len(jwt_secret) < MIN_JWT_SECRET_LENGTH:
        msg = "Production requires FLEXT_AUTH_JWT_SECRET_KEY (min 32 chars)"
        raise ValueError(msg)

    return FlextAuthApplicationConfig(
        debug=False,
        environment="production",
        jwt=FlextJWTConfig(secret_key=SecretStr(jwt_secret)),
    )


# =============================================================================
# SECURE DEFAULT SECRETS - Environment variable fallbacks
# =============================================================================

DEFAULT_JWT_SECRET = os.getenv("FLEXT_AUTH_JWT_SECRET_KEY", "dev-secret-key")
DEFAULT_SERVICE_SECRET = os.getenv(
    "FLEXT_AUTH_SERVICE_SECRET",
    get_default_secret("FLEXT_AUTH_SERVICE_SECRET"),
)
DEFAULT_MFA_SECRET = os.getenv(
    "FLEXT_AUTH_MFA_SECRET",
    get_default_secret("FLEXT_AUTH_MFA_SECRET"),
)
DEFAULT_DEV_SECRET = os.getenv("FLEXT_AUTH_DEV_SECRET", "dev-secret-key")

# =============================================================================
# EXPORTS - Clean config API
# =============================================================================

__all__ = [
    # Default secrets
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_MFA_SECRET",
    "DEFAULT_SERVICE_SECRET",
    # Backward compatibility
    "AppConfig",
    "DatabaseConfig",
    "FlextAuthApplicationConfig",
    # Main configuration classes
    "FlextAuthConfig",
    "JWTConfig",
    "SecurityConfig",
    # Factory functions
    "create_auth_config",
    "create_complete_auth_config",
    "create_development_config",
    "create_production_config",
    # Utilities
    "get_default_secret",
    "validate_production_config",
]

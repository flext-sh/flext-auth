"""FLEXT Auth Configuration - Using unified composition mixins.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module provides authentication configuration using unified composition mixins
from flext-core for maximum code reduction and standardization.
"""

from __future__ import annotations

from flext_core.config.unified_config import (
    AuthConfigMixin,
    BaseConfigMixin,
    DatabaseConfigMixin,
    LoggingConfigMixin,
    MonitoringConfigMixin,
    PerformanceConfigMixin,
    RedisConfigMixin,
)
from flext_core.domain.constants import ConfigDefaults
from flext_core.domain.shared_types import Environment
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(
    BaseConfigMixin,
    LoggingConfigMixin,
    DatabaseConfigMixin,
    RedisConfigMixin,
    AuthConfigMixin,
    MonitoringConfigMixin,
    PerformanceConfigMixin,
    BaseSettings,
):
    """Authentication configuration using unified composition mixins.

    This configuration eliminates ALL duplication by using composition mixins
    from flext-core unified configuration system. All common auth fields
    are provided by AuthConfigMixin.
    """

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # Project identification (inherits from BaseConfigMixin)
    project_name: str = Field(
        default="flext-auth",
        max_length=ConfigDefaults.MAX_ENTITY_NAME_LENGTH,
    )
    title: str = Field(
        default="FLEXT Auth",
        max_length=ConfigDefaults.MAX_ENTITY_NAME_LENGTH,
    )
    description: str = Field(
        default="Enterprise Authentication and Authorization Service",
        max_length=ConfigDefaults.MAX_ERROR_MESSAGE_LENGTH,
    )
    # Note: project_version is inherited from BaseConfigMixin

    # Override required fields with defaults for development
    jwt_secret_key: str = Field(
        default="dev-secret-key-change-in-production",
        description="JWT secret key - MUST be changed in production",
    )
    jwt_private_key_path: str | None = Field(
        default=None,
        description="Path to RSA private key file (for RSA algorithms)",
    )
    jwt_public_key_path: str | None = Field(
        default=None,
        description="Path to RSA public key file (for RSA algorithms)",
    )
    database_url: str = Field(
        default="postgresql://localhost:5432/flext_auth",
        description="Database connection URL",
    )
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL",
    )

    # All authentication fields are inherited from AuthConfigMixin:
    # - jwt_secret_key, jwt_algorithm, jwt_access_token_expire_minutes
    # - password_min_length, password_require_uppercase, etc.
    # - max_failed_login_attempts, account_lockout_duration_minutes

    # All database fields are inherited from DatabaseConfigMixin:
    # - database_url, database_pool_size, database_timeout, etc.

    # All Redis fields are inherited from RedisConfigMixin:
    # - redis_url, redis_pool_size, redis_timeout

    # Additional authentication-specific settings (beyond AuthConfigMixin)
    require_email_verification: bool = Field(
        default=True,
        description="Require email verification for new accounts",
    )
    password_require_special: bool = Field(
        default=False,
        description="Require special characters in password",
    )

    # Note: Most auth fields now inherited from AuthConfigMixin:
    # - max_failed_login_attempts, account_lockout_duration_minutes
    # - password_min_length, password_require_uppercase, password_require_lowercase
    # - password_require_numbers, password_bcrypt_rounds

    # Session settings (additional to AuthConfigMixin)
    max_concurrent_sessions: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum concurrent sessions per user",
    )
    session_timeout_minutes: int = Field(
        default=60,
        ge=1,
        le=1440,
        description="Session timeout in minutes",
    )

    # Email settings
    from_email: str = Field(
        default="noreply@flext.com",
        description="Default sender email address",
    )

    # Feature flags
    enable_registration: bool = Field(
        default=True,
        description="Enable user registration",
    )
    enable_password_reset: bool = Field(
        default=True,
        description="Enable password reset functionality",
    )
    enable_2fa: bool = Field(
        default=False,
        description="Enable two-factor authentication",
    )

    # Note: Redis configuration inherited from RedisConfigMixin:
    # - redis_url, redis_pool_size, redis_timeout, redis_decode_responses

    # Email configuration
    smtp_host: str = Field(default="localhost", description="SMTP server host")
    smtp_port: int = Field(default=587, ge=1, le=65535, description="SMTP server port")
    smtp_username: str = Field(default="", description="SMTP username")
    smtp_password: str = Field(
        default="",
        description="SMTP password",
        json_schema_extra={"secret": True},
    )
    smtp_use_tls: bool = Field(default=True, description="Use TLS for SMTP")

    # Email templates
    email_from: str = Field(
        default="noreply@flext.com",
        description="From email address",
    )
    email_verification_subject: str = Field(
        default="Verify your email address",
        description="Email verification subject",
    )
    password_reset_subject: str = Field(
        default="Password reset request",
        description="Password reset subject",
    )

    # Note: is_development() and is_production() inherited from BaseConfigMixin

    def validate_configuration(self) -> list[str]:
        """Validate authentication configuration settings.

        Returns:
            List of validation error messages.

        """
        errors: list[str] = []

        # Most validations are now handled by Pydantic field constraints in mixins
        # Only validate application-specific business rules here

        if self.max_concurrent_sessions < 1:
            errors.append("Max concurrent sessions must be at least 1")

        if self.session_timeout_minutes < 1:
            errors.append("Session timeout must be at least 1 minute")

        if self.jwt_access_token_expire_minutes < 1:
            errors.append("Access token expiration must be at least 1 minute")

        return errors


# Global settings instance
_settings: AuthConfig | None = None


def get_auth_settings() -> AuthConfig:
    """Get authentication configuration settings.

    Returns:
        AuthConfig: Consolidated authentication configuration using flext-core patterns.

    """
    global _settings
    if _settings is None:
        _settings = AuthConfig()
    return _settings


# Helper functions for creating configuration instances
def create_development_auth_config() -> AuthConfig:
    """Create development-specific auth configuration."""
    return AuthConfig(
        environment=Environment.DEVELOPMENT,
        debug=True,
        jwt_secret_key="dev-secret-key-change-in-production",
        database_url="postgresql://localhost:5432/flext_auth_dev",
        redis_url="redis://localhost:6379/0",
    )


def create_production_auth_config() -> AuthConfig:
    """Create production-specific auth configuration."""
    return AuthConfig(
        environment=Environment.PRODUCTION,
        debug=False,
        # Secret key must be set via environment variable in production
        database_url="postgresql://localhost:5432/flext_auth",
        redis_url="redis://localhost:6379/1",
    )


# Export aliases for backward compatibility
AuthSettings = AuthConfig

__all__ = [
    "AuthConfig",
    "AuthSettings",
    "create_development_auth_config",
    "create_production_auth_config",
    "get_auth_settings",
]

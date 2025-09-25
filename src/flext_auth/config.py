"""FLEXT Auth Configuration - Single unified class following FLEXT standards.

Provides unified configuration management for the FLEXT Auth ecosystem
using Pydantic Settings for environment variable support.
Single FlextAuthConfig class extending FlextConfig with all defaults from FlextAuthConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import (
    Field,
    SecretStr,
    field_validator,
    model_validator,
)

from flext_auth.constants import FlextAuthConstants
from flext_core import (
    FlextConfig,
    FlextResult,
    FlextService,
)


class FlextAuthConfig(FlextConfig):
    """Single Pydantic 2 Settings class for flext-auth extending FlextConfig.

    Follows standardized pattern:
    - Extends FlextConfig from flext-core
    - No nested classes within Config
    - All defaults from FlextAuthConstants
    - Dependency injection integration with flext-core container
    - Uses Pydantic 2.11+ features (SecretStr for secrets)
    """

    # Singleton pattern attributes
    _global_instance: ClassVar[FlextAuthConfig | None] = None
    _lock = FlextConfig._lock  # Reuse the lock from parent class

    # JWT Configuration using FlextAuthConstants for defaults
    jwt_auth_secret: SecretStr = Field(
        default_factory=lambda: SecretStr(FlextAuthConstants.JWT_SECRET_KEY),
        description="JWT secret key for token signing (sensitive)",
    )

    jwt_algorithm: str = Field(
        default=FlextAuthConstants.JWT_DEFAULT_ALGORITHM,
        description="JWT signing algorithm",
    )

    jwt_expiry_minutes: int = Field(
        default=FlextAuthConstants.JWT_DEFAULT_EXPIRY_MINUTES,
        ge=1,
        le=FlextAuthConstants.JWT_MAX_EXPIRY_MINUTES,
        description="JWT token expiry time in minutes",
    )

    jwt_issuer: str = Field(
        default=FlextAuthConstants.JWT_ISSUER_CLAIM, description="JWT token issuer"
    )

    jwt_audience: str = Field(
        default=FlextAuthConstants.JWT_AUDIENCE_CLAIM, description="JWT token audience"
    )

    # Password Configuration using FlextAuthConstants for defaults
    bcrypt_rounds: int = Field(
        default=FlextAuthConstants.BCRYPT_ROUNDS,
        ge=FlextAuthConstants.MIN_BCRYPT_ROUNDS,
        le=FlextAuthConstants.MAX_BCRYPT_ROUNDS,
        description="Bcrypt rounds for password hashing",
    )

    min_password_length: int = Field(
        default=FlextAuthConstants.MIN_PASSWORD_LENGTH,
        ge=6,
        description="Minimum password length",
    )

    max_password_length: int = Field(
        default=FlextAuthConstants.MAX_PASSWORD_LENGTH,
        description="Maximum password length",
    )

    # Security Configuration using FlextAuthConstants for defaults
    max_login_attempts: int = Field(
        default=FlextAuthConstants.MAX_LOGIN_ATTEMPTS,
        ge=1,
        le=10,
        description="Maximum failed login attempts before account lockout",
    )

    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.LOCKOUT_DURATION_MINUTES,
        ge=1,
        description="Account lockout duration in minutes",
    )

    # Session Configuration using FlextAuthConstants for defaults
    session_expiry_minutes: int = Field(
        default=FlextAuthConstants.DEFAULT_SESSION_EXPIRY_MINUTES,
        ge=1,
        le=FlextAuthConstants.MAX_SESSION_EXPIRY_MINUTES,
        description="Session expiry time in minutes",
    )

    max_sessions_per_user: int = Field(
        default=FlextAuthConstants.MAX_SESSIONS_PER_USER,
        ge=1,
        description="Maximum sessions per user",
    )

    # Logging Configuration using FlextAuthConstants for defaults
    enable_audit_logging: bool = Field(
        default=FlextAuthConstants.ENABLE_AUDIT_LOGGING,
        description="Enable detailed audit logging",
    )

    log_auth_attempts: bool = Field(
        default=FlextAuthConstants.LOG_AUTH_ATTEMPTS,
        description="Log authentication attempts",
    )

    log_auth_failures: bool = Field(
        default=FlextAuthConstants.LOG_AUTH_FAILURES,
        description="Log authentication failures",
    )

    log_auth_success: bool = Field(
        default=FlextAuthConstants.LOG_AUTH_SUCCESS,
        description="Log successful authentications",
    )

    mask_passwords: bool = Field(
        default=FlextAuthConstants.MASK_PASSWORDS,
        description="Mask passwords in log messages",
    )

    mask_tokens: bool = Field(
        default=FlextAuthConstants.MASK_TOKENS,
        description="Mask tokens in log messages",
    )

    # Performance Configuration using FlextAuthConstants for defaults
    track_auth_performance: bool = Field(
        default=FlextAuthConstants.TRACK_AUTH_PERFORMANCE,
        description="Track authentication performance",
    )

    auth_performance_threshold_warning: float = Field(
        default=FlextAuthConstants.AUTH_PERFORMANCE_THRESHOLD_WARNING,
        ge=0.0,
        description="Authentication performance warning threshold in milliseconds",
    )

    @property
    def session_expiry_hours(self) -> float:
        """Get session expiry time in hours (calculated from minutes)."""
        return self.session_expiry_minutes / 60.0

    @session_expiry_hours.setter
    def session_expiry_hours(self, value: float) -> None:
        """Set session expiry time from hours (converts to minutes)."""
        self.session_expiry_minutes = int(value * 60)

    # Pydantic 2.11 field validators
    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm is allowed."""
        if v not in FlextAuthConstants.JWT_ALLOWED_ALGORITHMS:
            valid_algorithms = ", ".join(FlextAuthConstants.JWT_ALLOWED_ALGORITHMS)
            msg = f"Invalid JWT algorithm: {v}. Must be one of: {valid_algorithms}"
            raise ValueError(msg)
        return v

    @field_validator("jwt_auth_secret")
    @classmethod
    def validate_jwt_secret(cls, v: SecretStr) -> SecretStr:
        """Validate and generate JWT secret if empty."""
        secret_value = v.get_secret_value()
        if not secret_value or not secret_value.strip():
            # Generate a secure JWT secret
            return SecretStr(secrets.token_urlsafe(32))

        if len(secret_value) < FlextAuthConstants.MIN_SECRET_KEY_LENGTH:
            msg = f"JWT secret must be at least {FlextAuthConstants.MIN_SECRET_KEY_LENGTH} characters"
            raise ValueError(msg)

        return v

    @field_validator("min_password_length")
    @classmethod
    def validate_min_password_length(cls, v: int) -> int:
        """Validate minimum password length."""
        if v < FlextAuthConstants.MIN_PASSWORD_LENGTH:
            msg = f"Password minimum length must be at least {FlextAuthConstants.MIN_PASSWORD_LENGTH}"
            raise ValueError(msg)
        return v

    @model_validator(mode="after")
    def validate_password_length_consistency(self) -> FlextAuthConfig:
        """Validate password length consistency."""
        if self.min_password_length > self.max_password_length:
            msg = (
                "Minimum password length cannot be greater than maximum password length"
            )
            raise ValueError(msg)
        return self

    @model_validator(mode="after")
    def validate_jwt_expiry_reasonable(self) -> FlextAuthConfig:
        """Validate JWT expiry is reasonable compared to session expiry."""
        if self.jwt_expiry_minutes > self.session_expiry_minutes:
            msg = "JWT expiry should not exceed session expiry"
            raise ValueError(msg)
        return self

    # Auth-specific methods
    def get_jwt_settings(self) -> dict[str, object]:
        """Get JWT-related settings (without exposing secrets)."""
        return {
            "algorithm": self.jwt_algorithm,
            "expiry_minutes": self.jwt_expiry_minutes,
            "issuer": self.jwt_issuer,
            "audience": self.jwt_audience,
            "secret_configured": self.jwt_auth_secret is not None,
        }

    def get_security_settings(self) -> dict[str, object]:
        """Get security-related settings."""
        return {
            "bcrypt_rounds": self.bcrypt_rounds,
            "max_login_attempts": self.max_login_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "min_password_length": self.min_password_length,
            "max_password_length": self.max_password_length,
        }

    def get_auth_logging_config(self) -> dict[str, object]:
        """Get authentication-specific logging configuration."""
        return {
            "enable_audit_logging": self.enable_audit_logging,
            "log_auth_attempts": self.log_auth_attempts,
            "log_auth_failures": self.log_auth_failures,
            "log_auth_success": self.log_auth_success,
            "mask_passwords": self.mask_passwords,
            "mask_tokens": self.mask_tokens,
            "track_auth_performance": self.track_auth_performance,
            "auth_performance_threshold_warning": self.auth_performance_threshold_warning,
        }

    @classmethod
    def create_for_environment(
        cls, environment: str, **overrides: object
    ) -> FlextAuthConfig:
        """Create configuration for specific environment."""
        return cls(environment=environment, **overrides)

    @classmethod
    def create_default(cls) -> FlextAuthConfig:
        """Create default configuration instance."""
        return cls()

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for authentication configuration."""
        if self.min_password_length < FlextAuthConstants.MIN_PASSWORD_LENGTH:
            return FlextResult[None].fail("Password minimum length must be at least 8")

        if self.max_login_attempts > FlextAuthConstants.MAX_LOGIN_ATTEMPTS:
            return FlextResult[None].fail("Max login attempts cannot exceed 5")

        if self.bcrypt_rounds < FlextAuthConstants.MIN_BCRYPT_ROUNDS:
            return FlextResult[None].fail(
                "Bcrypt rounds must be at least 10 for security"
            )

        if self.jwt_expiry_minutes > FlextAuthConstants.JWT_MAX_EXPIRY_MINUTES:
            return FlextResult[None].fail("JWT expiry cannot exceed 24 hours")

        return FlextResult[None].ok(None)

    # Singleton pattern override for proper typing
    @classmethod
    def get_global_instance(cls) -> FlextAuthConfig:
        """Get the global singleton instance of FlextAuthConfig."""
        if cls._global_instance is None:
            with cls._lock:
                if cls._global_instance is None:
                    cls._global_instance = cls()
        return cls._global_instance  # type: ignore[return-value]  # type: ignore[return-value]

    @classmethod
    def get_or_create_global(cls, **kwargs: object) -> FlextResult[FlextAuthConfig]:
        """Get or create the global singleton instance with optional parameters."""
        try:
            if cls._global_instance is None:
                with cls._lock:
                    if cls._global_instance is None:
                        cls._global_instance = cls(**kwargs)
            return FlextResult[FlextAuthConfig].ok(cls._global_instance)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(f"Failed to create FlextAuthConfig: {e}")

    def validate_configuration(self) -> FlextResult[None]:
        """Validate the current configuration instance."""
        return self.validate_business_rules()


class FlextAuthConfigService(FlextService):
    """Service class for FlextAuthConfig operations."""

    def __init__(self) -> None:
        """Initialize auth config service."""
        super().__init__()
        self._config = FlextAuthConfig.create_default()

    def execute(self) -> FlextResult[dict[str, object]]:
        """Execute auth config service operation."""
        return FlextResult[dict[str, object]].ok({
            "status": "operational",
            "service": "flext-auth-config",
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "2.0.0",
            "config": self._config.model_dump(
                exclude={"jwt_secret"}
            ),  # Exclude secrets
        })

    async def execute_async(self) -> FlextResult[dict[str, object]]:
        """Execute auth config service operation asynchronously."""
        return FlextResult[dict[str, object]].ok({
            "status": "operational",
            "service": "flext-auth-config",
            "timestamp": datetime.now(UTC).isoformat(),
            "version": "2.0.0",
            "config": self._config.model_dump(
                exclude={"jwt_secret"}
            ),  # Exclude secrets
        })


__all__ = [
    "FlextAuthConfig",
    "FlextAuthConfigService",
]

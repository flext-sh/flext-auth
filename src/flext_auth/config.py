"""FLEXT Auth Configuration - Single unified class following FLEXT standards.

Provides unified configuration management for the FLEXT Auth ecosystem
using Pydantic Settings for environment variable support.
Single FlextAuthConfig class extending FlextConfig with all defaults from FlextAuthConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
import threading
from datetime import UTC, datetime
from typing import ClassVar, cast

from pydantic import (
    Field,
    SecretStr,
    computed_field,
    field_validator,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from flext_auth.constants import FlextAuthConstants
from flext_core import (
    FlextConfig,
    FlextResult,
)


class FlextAuthConfig(FlextConfig):
    """Single Pydantic 2 Settings class for flext-auth extending FlextConfig.

    Follows standardized pattern:
    - Extends FlextConfig from flext-core
    - No nested classes within Config
    - All defaults from FlextAuthConstants
    - Uses enhanced singleton pattern with inverse dependency injection
    - Uses Pydantic 2.11+ features (SecretStr for secrets)
    """

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        case_sensitive=False,
        extra="allow",
        # Inherit enhanced Pydantic 2.11+ features from FlextConfig
        validate_assignment=True,
        str_strip_whitespace=True,
        json_schema_extra={
            "title": "FLEXT Auth Configuration",
            "description": "Enterprise authentication configuration extending FlextConfig",
        },
    )

    # JWT Configuration using FlextAuthConstants for defaults
    jwt_auth_secret: SecretStr = Field(
        default_factory=lambda: SecretStr(FlextAuthConstants.Jwt.SECRET_KEY),
        description="JWT secret key for token signing (sensitive)",
    )

    jwt_algorithm: str = Field(
        default=FlextAuthConstants.Jwt.DEFAULT_ALGORITHM,
        description="JWT signing algorithm",
    )

    jwt_expiry_minutes: int = Field(
        default=FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES,
        ge=1,
        le=FlextAuthConstants.Jwt.MAX_EXPIRY_MINUTES,
        description="JWT token expiry time in minutes",
    )

    jwt_issuer: str = Field(
        default=FlextAuthConstants.Jwt.ISSUER_CLAIM, description="JWT token issuer"
    )

    jwt_audience: str = Field(
        default=FlextAuthConstants.Jwt.AUDIENCE_CLAIM, description="JWT token audience"
    )

    # Password Configuration using FlextAuthConstants for defaults
    bcrypt_rounds: int = Field(
        default=FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS,
        ge=FlextAuthConstants.Credentials.Password.MIN_BCRYPT_ROUNDS,
        le=FlextAuthConstants.Credentials.Password.MAX_BCRYPT_ROUNDS,
        description="Bcrypt rounds for password hashing",
    )

    min_password_length: int = Field(
        default=FlextAuthConstants.Credentials.Password.MIN_LENGTH,
        ge=6,
        description="Minimum password length",
    )

    max_password_length: int = Field(
        default=FlextAuthConstants.Credentials.Password.MAX_LENGTH,
        description="Maximum password length",
    )

    # Security Configuration using FlextAuthConstants for defaults
    max_login_attempts: int = Field(
        default=FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS,
        ge=1,
        le=10,
        description="Maximum failed login attempts before account lockout",
    )

    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.Security.LOCKOUT_DURATION_MINUTES,
        ge=1,
        description="Account lockout duration in minutes",
    )

    # Session Configuration using FlextAuthConstants for defaults
    session_expiry_minutes: int = Field(
        default=FlextAuthConstants.Session.DEFAULT_EXPIRY_MINUTES,
        ge=1,
        le=FlextAuthConstants.Session.MAX_EXPIRY_MINUTES,
        description="Session expiry time in minutes",
    )

    max_sessions_per_user: int = Field(
        default=FlextAuthConstants.Session.MAX_SESSIONS_PER_USER,
        ge=1,
        description="Maximum sessions per user",
    )

    # Logging Configuration using FlextAuthConstants for defaults
    enable_audit_logging: bool = Field(
        default=FlextAuthConstants.Logging.Audit.ENABLE_AUDIT_LOGGING,
        description="Enable detailed audit logging",
    )

    log_auth_attempts: bool = Field(
        default=FlextAuthConstants.Logging.Audit.LOG_AUTH_ATTEMPTS,
        description="Log authentication attempts",
    )

    log_auth_failures: bool = Field(
        default=FlextAuthConstants.Logging.Audit.LOG_AUTH_FAILURES,
        description="Log authentication failures",
    )

    log_auth_success: bool = Field(
        default=FlextAuthConstants.Logging.Audit.LOG_AUTH_SUCCESS,
        description="Log successful authentications",
    )

    mask_passwords: bool = Field(
        default=FlextAuthConstants.Logging.Security.MASK_PASSWORDS,
        description="Mask passwords in log messages",
    )

    mask_tokens: bool = Field(
        default=FlextAuthConstants.Logging.Security.MASK_TOKENS,
        description="Mask tokens in log messages",
    )

    # Performance Configuration using FlextAuthConstants for defaults
    track_auth_performance: bool = Field(
        default=FlextAuthConstants.Logging.Performance.TRACK_AUTH_PERFORMANCE,
        description="Track authentication performance",
    )

    auth_performance_threshold_warning: float = Field(
        default=FlextAuthConstants.Logging.Performance.THRESHOLD_WARNING,
        ge=0.0,
        description="Authentication performance warning threshold in milliseconds",
    )

    # Additional configuration fields expected by tests
    enable_rate_limiting: bool = Field(
        default=True,
        description="Enable rate limiting for authentication requests",
    )

    session_cleanup_interval_minutes: int = Field(
        default=FlextAuthConstants.Session.CLEANUP_INTERVAL_MINUTES,
        description="Interval for cleaning up expired sessions in minutes",
    )

    require_password_complexity: bool = Field(
        default=True,
        description="Require complex passwords with multiple character types",
    )

    min_password_score: int = Field(
        default=FlextAuthConstants.Credentials.Password.MIN_SCORE,
        description="Minimum password complexity score",
    )

    max_requests_per_minute: int = Field(
        default=FlextAuthConstants.Security.MAX_REQUESTS_PER_MINUTE,
        description="Maximum authentication requests per minute",
    )

    max_requests_per_hour: int = Field(
        default=FlextAuthConstants.Security.MAX_REQUESTS_PER_HOUR,
        description="Maximum authentication requests per hour",
    )

    enable_email_verification: bool = Field(
        default=True,
        description="Enable email verification for user registration",
    )

    enable_password_history: bool = Field(
        default=True,
        description="Enable password history tracking",
    )

    @computed_field
    def session_expiry_hours(self) -> float:
        """Get session expiry time in hours (calculated from minutes)."""
        return self.session_expiry_minutes / 60.0

    # Pydantic 2.11 field validators
    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm is allowed."""
        if v not in FlextAuthConstants.Jwt.ALLOWED_ALGORITHMS:
            valid_algorithms = ", ".join(FlextAuthConstants.Jwt.ALLOWED_ALGORITHMS)
            msg = f"Invalid JWT algorithm: {v}. Must be one of: {valid_algorithms}"
            raise ValueError(msg)
        return v

    @field_validator("jwt_auth_secret")
    @classmethod
    def validate_jwt_secret(cls, v: SecretStr) -> SecretStr:
        """Validate and generate JWT secret if empty."""
        secret_value = v.get_secret_value()
        if not secret_value or not secret_value.strip():
            # Generate a secure JWT secret using secrets module
            # Note: Using secrets directly to avoid circular import
            return SecretStr(secrets.token_urlsafe(32))

        if len(secret_value) < FlextAuthConstants.Jwt.MIN_SECRET_KEY_LENGTH:
            msg = f"JWT secret must be at least {FlextAuthConstants.Jwt.MIN_SECRET_KEY_LENGTH} characters"
            raise ValueError(msg)

        return v

    @field_validator("min_password_length")
    @classmethod
    def validate_min_password_length(cls, v: int) -> int:
        """Validate minimum password length."""
        if v < FlextAuthConstants.Credentials.Password.MIN_LENGTH:
            msg = f"Password minimum length must be at least {FlextAuthConstants.Credentials.Password.MIN_LENGTH}"
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
            "jwt_algorithm": self.jwt_algorithm,  # Add the expected key
            "jwt_expiry_minutes": self.jwt_expiry_minutes,  # Add the expected key
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
        """Create configuration for specific environment using enhanced singleton pattern."""
        return cast(
            "FlextAuthConfig",
            cls.get_or_create_shared_instance(
                project_name="flext-auth", environment=environment, **overrides
            ),
        )

    @classmethod
    def create_default(cls) -> FlextAuthConfig:
        """Create default configuration instance using enhanced singleton pattern."""
        return cls()

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for authentication configuration."""
        if (
            self.min_password_length
            < FlextAuthConstants.Credentials.Password.MIN_LENGTH
        ):
            return FlextResult[None].fail("Password minimum length must be at least 8")

        if self.max_login_attempts > FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS:
            return FlextResult[None].fail("Max login attempts cannot exceed 5")

        if (
            self.bcrypt_rounds
            < FlextAuthConstants.Credentials.Password.MIN_BCRYPT_ROUNDS
        ):
            return FlextResult[None].fail(
                "Bcrypt rounds must be at least 10 for security"
            )

        if self.jwt_expiry_minutes > FlextAuthConstants.Jwt.MAX_EXPIRY_MINUTES:
            return FlextResult[None].fail("JWT expiry cannot exceed 24 hours")

        return FlextResult[None].ok(None)

    # Singleton pattern implementation
    _global_instance: ClassVar[FlextAuthConfig | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    @classmethod
    def get_global_instance(cls) -> FlextAuthConfig:
        """Get the global singleton instance."""
        if cls._global_instance is None:
            with cls._lock:
                if cls._global_instance is None:
                    cls._global_instance = cls()
        return cls._global_instance

    @classmethod
    def set_global_instance(cls, instance: FlextConfig) -> None:
        """Set the global singleton instance of FlextAuthConfig."""
        if isinstance(instance, FlextAuthConfig):
            cls._global_instance = instance
        else:
            msg = "Instance must be of type FlextAuthConfig"
            raise TypeError(msg)

    @classmethod
    def reset_global_instance(cls) -> None:
        """Reset the global FlextAuthConfig instance (mainly for testing)."""
        cls._global_instance = None

    @classmethod
    def get_or_create_global(cls, **kwargs: object) -> FlextResult[FlextAuthConfig]:
        """Get or create the global singleton instance with optional parameters using enhanced pattern."""
        try:
            instance = cast(
                "FlextAuthConfig",
                cls.get_or_create_shared_instance(project_name="flext-auth", **kwargs),
            )
            return FlextResult[FlextAuthConfig].ok(instance)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to create FlextAuthConfig: {e}"
            )

    def validate_configuration(self) -> FlextResult[None]:
        """Validate the current configuration instance."""
        return self.validate_business_rules()

    # Service operations (previously FlextAuthConfigService) - unified pattern
    class _ConfigServiceHelper:
        """Nested helper class for auth config service operations."""

        @staticmethod
        def execute_service_operation(
            config: FlextAuthConfig,
        ) -> FlextResult[dict[str, object]]:
            """Execute auth config service operation."""
            return FlextResult[dict[str, object]].ok({
                "status": "operational",
                "service": "flext-auth-config",
                "timestamp": datetime.now(UTC).isoformat(),
                "version": "2.0.0",
                "config": config.model_dump(exclude={"jwt_secret"}),  # Exclude secrets
            })

    def execute_as_service(self) -> FlextResult[dict[str, object]]:
        """Execute config as service operation using nested helper."""
        return self._ConfigServiceHelper.execute_service_operation(self)

    @classmethod
    def create_with_overrides(
        cls,
        jwt_expiry_minutes: int | None = None,
        bcrypt_rounds: int | None = None,
        max_login_attempts: int | None = None,
        session_expiry_minutes: int | None = None,
        environment: str = "development",
        **kwargs: object,
    ) -> FlextAuthConfig:
        """Create configuration instance with specific overrides."""
        overrides: dict[str, object] = {}
        if jwt_expiry_minutes is not None:
            overrides["jwt_expiry_minutes"] = jwt_expiry_minutes
        if bcrypt_rounds is not None:
            overrides["bcrypt_rounds"] = bcrypt_rounds
        if max_login_attempts is not None:
            overrides["max_login_attempts"] = max_login_attempts
        if session_expiry_minutes is not None:
            overrides["session_expiry_minutes"] = session_expiry_minutes

        overrides.update(kwargs)

        return cls.create_for_environment(environment=environment, **overrides)


__all__ = [
    "FlextAuthConfig",
]

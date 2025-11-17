"""FLEXT Auth Configuration - Generic Pydantic configuration with flext-core integration.

Single FlextAuthConfig class using Pydantic ConfigDict with environment variable
override support, validation, and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar, Self

from flext_core import FlextConfig, FlextResult
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import SettingsConfigDict

from flext_auth.constants import FlextAuthConstants


class FlextAuthConfig(FlextConfig):
    """Generic authentication configuration using Pydantic and flext-core patterns.

    All auth configuration unified in single class with environment override,
    validation, and sensible defaults embedded directly (not from constants).
    """

    _global_instance: ClassVar[FlextAuthConfig | None] = None

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        case_sensitive=False,
        validate_assignment=True,
        env_file=".env",
        extra="ignore",
        validate_default=True,
    )

    # Security: Generic secret and algorithm
    auth_secret: SecretStr = Field(
        default=SecretStr("flext-auth-default-secret-key-change-in-production"),
        description="Generic secret key",
    )
    algorithm: str = Field(
        default=FlextAuthConstants.ALGORITHM_DEFAULT,
        description="Cryptographic algorithm",
    )
    expiry_minutes: int = Field(
        default=FlextAuthConstants.EXPIRY_DEFAULT_MINUTES,
        ge=1,
        le=FlextAuthConstants.EXPIRY_MAX_MINUTES,
        description="Default expiry time",
    )
    issuer: str = Field(
        default=FlextAuthConstants.DEFAULT_ISSUER, description="Token issuer"
    )
    audience: str = Field(
        default=FlextAuthConstants.DEFAULT_AUDIENCE, description="Token audience"
    )

    # Credential Processing
    hash_rounds: int = Field(
        default=FlextAuthConstants.HASH_ROUNDS_DEFAULT,
        ge=FlextAuthConstants.HASH_ROUNDS_MIN,
        le=FlextAuthConstants.HASH_ROUNDS_MAX,
        description="Credential hashing rounds",
    )
    min_credential_length: int = Field(
        default=FlextAuthConstants.CREDENTIAL_MIN_LENGTH,
        ge=1,
        description="Minimum credential length",
    )
    max_credential_length: int = Field(
        default=FlextAuthConstants.CREDENTIAL_MAX_LENGTH,
        ge=1,
        description="Maximum credential length",
    )

    # Security Policies
    max_attempts: int = Field(
        default=FlextAuthConstants.MAX_ATTEMPTS_DEFAULT,
        ge=1,
        description="Max attempts before lockout",
    )
    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.LOCKOUT_DURATION_MINUTES,
        ge=1,
        description="Lockout duration",
    )

    # Session Management
    session_expiry_minutes: int = Field(
        default=FlextAuthConstants.SESSION_EXPIRY_DEFAULT_MINUTES,
        ge=1,
        le=FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES,
        description="Session expiry",
    )
    max_sessions_per_identity: int = Field(
        default=FlextAuthConstants.MAX_SESSIONS_DEFAULT,
        ge=1,
        description="Max concurrent sessions",
    )

    # Audit & Logging
    enable_audit_logging: bool = Field(
        default=True,
        description="Enable audit logging",
    )
    log_attempts: bool = Field(default=True, description="Log attempts")
    log_failures: bool = Field(default=True, description="Log failures")
    log_success: bool = Field(default=False, description="Log success")
    mask_credentials: bool = Field(default=True, description="Mask credentials")
    mask_tokens: bool = Field(default=True, description="Mask tokens")

    # Performance & Rate Limiting
    track_performance: bool = Field(
        default=False,
        description="Track performance",
    )
    performance_warning_threshold: float = Field(
        default=FlextAuthConstants.PERFORMANCE_THRESHOLD_MS,
        ge=0.0,
        description="Performance warning threshold (ms)",
    )
    enable_rate_limiting: bool = Field(
        default=False,
        description="Enable rate limiting",
    )
    max_requests_per_minute: int = Field(
        default=FlextAuthConstants.MAX_REQUESTS_PER_MINUTE,
        ge=1,
        description="Max requests/minute",
    )
    max_requests_per_hour: int = Field(
        default=FlextAuthConstants.MAX_REQUESTS_PER_HOUR,
        ge=1,
        description="Max requests/hour",
    )

    # Flexible Features
    require_complexity: bool = Field(
        default=False,
        description="Require complexity",
    )
    min_score: int = Field(
        default=2,
        ge=0,
        le=4,
        description="Min complexity score",
    )
    enable_verification: bool = Field(
        default=False,
        description="Enable verification",
    )
    enable_history: bool = Field(default=False, description="Enable history")

    # Environment
    environment: str = Field(
        default="development",
        description="Environment name (development, staging, production)",
    )

    @classmethod
    def create_with_overrides(cls, **overrides: object) -> FlextResult[FlextAuthConfig]:
        """Create config instance with overrides."""
        try:
            # Create instance with overrides - Pydantic will validate
            instance = cls(**overrides)
            return FlextResult[FlextAuthConfig].ok(instance)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(str(e))

    def get_jwt_settings(self) -> dict[str, str | int | bool]:
        """Get JWT-specific settings."""
        return {
            "algorithm": self.algorithm,
            "expiry_minutes": self.expiry_minutes,
            "issuer": self.issuer,
            "audience": self.audience,
            "secret_configured": len(self.auth_secret.get_secret_value())
            >= FlextAuthConstants.SECRET_MIN_LENGTH,
        }

    def get_security_settings(self) -> dict[str, int | bool]:
        """Get security-related settings."""
        return {
            "hash_rounds": self.hash_rounds,
            "max_attempts": self.max_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "min_credential_length": self.min_credential_length,
            "max_credential_length": self.max_credential_length,
        }

    @model_validator(mode="after")
    def _validate_model(self) -> Self:
        """Pydantic model validator for automatic validation."""
        secret_len = len(self.auth_secret.get_secret_value())
        if secret_len < FlextAuthConstants.SECRET_MIN_LENGTH:
            msg = f"Secret must be ≥{FlextAuthConstants.SECRET_MIN_LENGTH} chars, got {secret_len}"
            raise ValueError(msg)

        if self.min_credential_length > self.max_credential_length:
            msg = "Min credential length > max"
            raise ValueError(msg)

        if self.session_expiry_minutes > FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES:
            msg = f"Session expiry > {FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES}min (30 days)"
            raise ValueError(msg)

        # JWT expiry should not exceed session expiry
        if self.expiry_minutes > self.session_expiry_minutes:
            msg = "JWT expiry should not exceed session expiry"
            raise ValueError(msg)

        return self

    def validate_configuration(self) -> FlextResult[bool]:
        """Validate configuration after initialization.

        Returns:
            FlextResult[bool]: True if valid, False with error message if invalid

        """
        try:
            # Pydantic v2 validates automatically on model creation
            # Re-validate by creating a new instance from current data
            self.model_validate(self.model_dump())
            # Check validation constraints manually
            secret_len = len(self.auth_secret.get_secret_value())
            if secret_len < FlextAuthConstants.SECRET_MIN_LENGTH:
                msg = f"Secret must be ≥{FlextAuthConstants.SECRET_MIN_LENGTH} chars, got {secret_len}"
                return FlextResult[bool].fail(msg)

            if self.min_credential_length > self.max_credential_length:
                return FlextResult[bool].fail("Min credential length > max")

            if (
                self.session_expiry_minutes
                > FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES
            ):
                msg = f"Session expiry > {FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES}min (30 days)"
                return FlextResult[bool].fail(msg)

            if self.expiry_minutes > self.session_expiry_minutes:
                return FlextResult[bool].fail(
                    "JWT expiry should not exceed session expiry"
                )

            return FlextResult[bool].ok(True)
        except ValueError as e:
            return FlextResult[bool].fail(str(e))
        except Exception as e:
            return FlextResult[bool].fail(f"Validation error: {e}")

    @classmethod
    def set_global_instance(cls, instance: FlextAuthConfig) -> None:
        """Set the global instance.

        Args:
            instance: FlextAuthConfig instance to set as global

        Raises:
            TypeError: If instance is not of type FlextAuthConfig

        """
        if not isinstance(instance, FlextAuthConfig):
            msg = "Instance must be of type FlextAuthConfig"
            raise TypeError(msg)
        cls._global_instance = instance

    @classmethod
    def get_or_create_global(
        cls,
        **kwargs: str | int | bool | SecretStr | None,
    ) -> FlextResult[FlextAuthConfig]:
        """Get or create global instance with optional overrides.

        Args:
        **kwargs: Configuration overrides with proper types

        Returns:
        FlextResult containing the config instance

        """
        try:
            # If instance exists and no kwargs provided, return it
            if not kwargs:
                if cls._global_instance is not None:
                    return FlextResult.ok(cls._global_instance)
                # Create default instance if none exists
                instance = cls()
                cls._global_instance = instance
                return FlextResult.ok(instance)
            # If kwargs provided, always create new instance with overrides
            instance = cls(**kwargs)
            # Set as global instance
            cls._global_instance = instance
            return FlextResult.ok(instance)
        except Exception as e:
            return FlextResult.fail(f"Failed to create config: {e}")

    def to_provider_config(self) -> dict[str, object]:
        """Convert config to provider configuration dict.

        Returns provider configuration without using model_dump().
        Directly accesses config properties to build the dict.
        """
        config_dict: dict[str, object] = {
            "algorithm": self.algorithm,
            "expiry_minutes": self.expiry_minutes,
            "issuer": self.issuer,
            "audience": self.audience,
            "secret_key": self.auth_secret.get_secret_value(),
            "hash_rounds": self.hash_rounds,
            "min_credential_length": self.min_credential_length,
            "max_credential_length": self.max_credential_length,
            "max_attempts": self.max_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "session_expiry_minutes": self.session_expiry_minutes,
            "max_sessions_per_identity": self.max_sessions_per_identity,
        }

        return config_dict


__all__ = ["FlextAuthConfig"]

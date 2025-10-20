"""FLEXT Auth Configuration - Generic Pydantic configuration with flext-core integration.

Single FlextAuthConfig class using Pydantic ConfigDict with environment variable
override support, validation, and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self

from flext_core import FlextConfig, FlextResult
from pydantic import Field, SecretStr, model_validator
from pydantic_settings import SettingsConfigDict

from flext_auth.constants import FlextAuthConstants


class FlextAuthConfig(FlextConfig):
    """Generic authentication configuration using Pydantic and flext-core patterns.

    All auth configuration unified in single class with environment override,
    validation, and sensible defaults embedded directly (not from constants).
    """

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

    # Advanced Features
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

    # Legacy property names for backward compatibility
    @property
    def max_login_attempts(self) -> int:
        """Maximum login attempts (alias for max_attempts)."""
        return self.max_attempts

    @property
    def jwt_expiry_minutes(self) -> int:
        """Legacy property for jwt_expiry_minutes."""
        return self.expiry_minutes

    @property
    def jwt_algorithm(self) -> str:
        """Legacy property for jwt_algorithm."""
        return self.algorithm

    @property
    def jwt_auth_secret(self) -> SecretStr:
        """Legacy property for jwt_auth_secret."""
        return self.auth_secret

    @property
    def bcrypt_rounds(self) -> int:
        """Legacy property for bcrypt_rounds."""
        return self.hash_rounds

    @property
    def environment(self) -> str:
        """Get current environment."""
        return "development"  # Default for now

    @classmethod
    def create_with_overrides(cls, **overrides: object) -> FlextResult[Self]:
        """Create config instance with overrides."""
        try:
            # Validate overrides using base class method
            validation_result = cls.validate_overrides(cls(), **overrides)
            if validation_result.is_failure:
                return FlextResult[Self].fail(
                    validation_result.error or "Validation failed"
                )

            # Create a new instance and apply validated overrides
            instance = cls.__new__(cls)
            # Initialize with defaults first
            super(cls, instance).__init__()

            # Apply validated overrides
            for key, value in validation_result.unwrap().items():
                setattr(instance, key, value)

            return FlextResult[Self].ok(instance)
        except Exception as e:
            return FlextResult[Self].fail(str(e))

    def get_jwt_settings(self) -> dict[str, str | int]:
        """Get JWT-specific settings."""
        return {
            "algorithm": self.algorithm,
            "jwt_expiry_minutes": self.expiry_minutes,
            "expiry_minutes": self.expiry_minutes,
            "issuer": self.issuer,
            "audience": self.audience,
        }

    def get_security_settings(self) -> dict[str, int | bool]:
        """Get security-related settings."""
        return {
            "hash_rounds": self.hash_rounds,
            "bcrypt_rounds": self.hash_rounds,
            "max_attempts": self.max_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
        }

    @model_validator(mode="after")
    def validate_configuration(self) -> Self:
        """Validate configuration after initialization."""
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

        return self

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
            # If instance exists, return it
            instance = cls.get_global_instance()
            return FlextResult.ok(instance)
        except Exception:
            # Create new instance with provided kwargs
            try:
                instance = cls(**kwargs)
                # Set as global instance
                cls._global_instance = instance
                return FlextResult.ok(instance)
            except Exception as e:
                return FlextResult.fail(f"Failed to create config: {e}")

    @property
    def jwt_secret(self) -> SecretStr:
        """Alias for auth_secret for backward compatibility."""
        return self.auth_secret

    @jwt_secret.setter
    def jwt_secret(self, value: str | SecretStr) -> None:
        """Set auth_secret via jwt_secret alias."""
        if isinstance(value, str):
            self.auth_secret = SecretStr(value)
        else:
            self.auth_secret = value

    # Additional backward compatibility properties for tests
    @property
    def min_password_length(self) -> int:
        """Alias for min_credential_length."""
        return self.min_credential_length

    @property
    def max_password_length(self) -> int:
        """Alias for max_credential_length."""
        return self.max_credential_length

    @property
    def jwt_issuer(self) -> str:
        """Alias for issuer."""
        return self.issuer

    @property
    def jwt_audience(self) -> str:
        """Alias for audience."""
        return self.audience

    # Class method for backward compatibility
    @classmethod
    def create(cls, **kwargs: str | int | bool | SecretStr | None) -> Self:
        """Create config instance (alias for constructor)."""
        return cls(**kwargs)


__all__ = ["FlextAuthConfig"]

"""FLEXT Auth Configuration - Generic Pydantic configuration with flext-core integration.

Single FlextAuthSettings class using Pydantic ConfigDict with environment variable
override support, validation, and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Self

from flext_auth import c
from flext_core import FlextSettings, r, t
from pydantic import Field, SecretStr


@FlextSettings.auto_register("auth")
class FlextAuthSettings(FlextSettings):
    """Generic authentication configuration using Pydantic and flext-core patterns.

    **ARCHITECTURAL PATTERN**: Zero-Boilerplate Auto-Registration

    This class uses FlextSettings.AutoConfig for automatic:
    - Singleton pattern (thread-safe)
    - Namespace registration (accessible via config.auth)
    - Test reset capability (_reset_instance)

    All auth configuration unified in single class with validation
    and sensible defaults embedded directly (not from constants).
    """

    # Security: Generic secret and algorithm
    auth_secret: SecretStr = Field(
        default=SecretStr("flext-auth-default-secret-key-change-in-production"),
        description="Generic secret key",
    )
    algorithm: str = Field(
        default="HS256",
        description="Cryptographic algorithm",
    )
    expiry_minutes: int = Field(
        default=c.Auth.DEFAULT_SESSION_EXPIRY_MINUTES,
        ge=1,
        le=c.Auth.SESSION_EXPIRY_MAX_MINUTES,
        description="Default expiry time",
    )
    issuer: str = Field(
        default="flext-auth",
        description="Token issuer",
    )
    audience: str = Field(
        default="flext-api",
        description="Token audience",
    )

    # Credential Processing
    hash_rounds: int = Field(
        default=c.Auth.Credentials.Password.BCRYPT_ROUNDS,
        ge=c.Auth.HASH_ROUNDS_MIN,
        le=c.Auth.HASH_ROUNDS_MAX,
        description="Credential hashing rounds",
    )
    min_credential_length: int = Field(
        default=c.Auth.CREDENTIAL_MIN_LENGTH,
        ge=1,
        description="Minimum credential length",
    )
    max_credential_length: int = Field(
        default=c.Auth.CREDENTIAL_MAX_LENGTH,
        ge=1,
        description="Maximum credential length",
    )

    # Security Policies
    max_attempts: int = Field(
        default=c.Auth.MAX_ATTEMPTS_DEFAULT,
        ge=1,
        description="Max attempts before lockout",
    )
    lockout_duration_minutes: int = Field(
        default=c.Auth.LOCKOUT_DURATION_MINUTES,
        ge=1,
        description="Lockout duration",
    )

    # Session Management
    session_expiry_minutes: int = Field(
        default=c.Auth.SESSION_EXPIRY_DEFAULT_MINUTES,
        ge=1,
        le=c.Auth.SESSION_EXPIRY_MAX_MINUTES,
        description="Session expiry",
    )
    max_sessions_per_identity: int = Field(
        default=c.Auth.MAX_SESSIONS_DEFAULT,
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
        default=c.Auth.PERFORMANCE_THRESHOLD_MS,
        ge=0.0,
        description="Performance warning threshold (ms)",
    )
    enable_rate_limiting: bool = Field(
        default=False,
        description="Enable rate limiting",
    )
    max_requests_per_minute: int = Field(
        default=c.Auth.MAX_REQUESTS_PER_MINUTE,
        ge=1,
        description="Max requests/minute",
    )
    max_requests_per_hour: int = Field(
        default=c.Auth.MAX_REQUESTS_PER_HOUR,
        ge=1,
        description="Max requests/hour",
    )

    # Flexible Features
    require_complexity: bool = Field(
        default=False,
        description="Require complexity",
    )
    min_score: int = Field(
        default=c.Auth.Credentials.Password.MIN_SCORE,
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
    def create_with_overrides(
        cls, **overrides: t.GeneralValueType
    ) -> r[FlextAuthSettings]:
        """Create config instance with overrides."""
        try:
            # Create instance with overrides - Pydantic will validate
            instance = cls.model_validate(overrides)
            return r[FlextAuthSettings].ok(instance)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as e:
            return r[FlextAuthSettings].fail(str(e))

    def get_jwt_settings(self) -> Mapping[str, str | int | bool]:
        """Get JWT-specific settings."""
        return {
            "algorithm": self.algorithm,
            "expiry_minutes": self.expiry_minutes,
            "issuer": self.issuer,
            "audience": self.audience,
            "secret_configured": len(self.auth_secret.get_secret_value())
            >= c.Auth.SECRET_MIN_LENGTH,
        }

    def get_security_settings(self) -> Mapping[str, int | bool]:
        """Get security-related settings."""
        return {
            "hash_rounds": self.hash_rounds,
            "max_attempts": self.max_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "min_credential_length": self.min_credential_length,
            "max_credential_length": self.max_credential_length,
        }

    # @model_validator(mode="after")
    def _validate_model(self) -> Self:
        """Pydantic model validator for automatic validation."""
        # Validate auth_secret exposes SecretStr API with proper length
        try:
            secret_value = self.auth_secret.get_secret_value()
        except AttributeError as exc:
            msg = "auth_secret must expose get_secret_value()"
            raise TypeError(msg) from exc

        secret_len = len(secret_value)
        if secret_len < c.Auth.SECRET_MIN_LENGTH:
            msg = f"Secret must be ≥{c.Auth.SECRET_MIN_LENGTH} chars, got {secret_len}"
            raise ValueError(msg)

        if self.min_credential_length > self.max_credential_length:
            msg = "Min credential length > max"
            raise ValueError(msg)

        if self.session_expiry_minutes > c.Auth.SESSION_EXPIRY_MAX_MINUTES:
            msg = f"Session expiry > {c.Auth.SESSION_EXPIRY_MAX_MINUTES}min (30 days)"
            raise ValueError(msg)

        # JWT expiry should not exceed session expiry
        if self.expiry_minutes > self.session_expiry_minutes:
            msg = "JWT expiry should not exceed session expiry"
            raise ValueError(msg)

        return self

    def validate_auth_configuration(self) -> r[bool]:
        """Validate auth configuration after initialization.

        Returns:
            r[bool]: True if valid, False with error message if invalid

        Note: Named validate_auth_configuration to avoid overriding the
        parent class validate_configuration which returns Self.

        """
        try:
            # Pydantic v2 validates automatically on model creation
            # Re-validate by creating a new instance from current data
            self.model_validate(self.model_dump())
            # Check validation constraints manually
            secret_len = len(self.auth_secret.get_secret_value())
            if secret_len < c.Auth.SECRET_MIN_LENGTH:
                msg = f"Secret must be ≥{c.Auth.SECRET_MIN_LENGTH} chars, got {secret_len}"
                return r[bool].fail(msg)

            if self.min_credential_length > self.max_credential_length:
                return r[bool].fail("Min credential length > max")

            if self.session_expiry_minutes > c.Auth.SESSION_EXPIRY_MAX_MINUTES:
                msg = (
                    f"Session expiry > {c.Auth.SESSION_EXPIRY_MAX_MINUTES}min (30 days)"
                )
                return r[bool].fail(msg)

            if self.expiry_minutes > self.session_expiry_minutes:
                return r[bool].fail("JWT expiry should not exceed session expiry")

            return r[bool].ok(value=True)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as e:
            return r[bool].fail(f"Validation error: {e}")

    @classmethod
    def get_or_create_global(
        cls,
        **kwargs: t.GeneralValueType,
    ) -> r[FlextAuthSettings]:
        """Get or create global instance with optional overrides.

        Args:
        **kwargs: Configuration overrides with proper types

        Returns:
        FlextResult containing the config instance

        Note: AutoConfig provides get_instance() for singleton pattern.
        This method is kept for backward compatibility.

        """
        try:
            # Use FlextSettings singleton pattern
            if not kwargs:
                instance = cls()
                return r.ok(instance)
            # If kwargs provided, create new instance with overrides
            instance = cls.model_validate(kwargs)
            # Note: AutoConfig manages singleton internally, but we can't override it here
            # For overrides, return the new instance (caller should use get_instance() for singleton)
            return r.ok(instance)
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as e:
            return r.fail(f"Failed to create config: {e}")

    def to_provider_config(self) -> Mapping[str, t.JsonValue]:
        """Convert config to provider configuration dict.

        Returns provider configuration without using model_dump().
        Directly accesses config properties to build the dict.
        """
        config_dict: dict[str, t.JsonValue] = {
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


__all__ = ["FlextAuthSettings"]

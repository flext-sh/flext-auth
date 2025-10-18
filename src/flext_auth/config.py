"""FLEXT Auth Configuration - Generic pydantic config with flext-core integration.

Uses Python 3.13+ syntax, flext patterns directly, and consolidated generic fields
for maximum maintainability. Single FlextAuthConfig class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Self

from flext_core import FlextConfig
from pydantic import Field, SecretStr, computed_field, model_validator
from pydantic_settings import SettingsConfigDict

from flext_auth.constants import FlextAuthConstants


class FlextAuthConfig(FlextConfig):
    """Generic auth configuration using flext-core patterns and pydantic.

    Python 3.13+ features, SOLID principles, minimal line count through consolidation.
    Domain-agnostic configuration for any authentication system.
    """

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        case_sensitive=False,
        validate_assignment=True,
        env_file=".env",
        extra="ignore",
        validate_default=True,
    )

    # =========================================================================
    # CONSOLIDATED GENERIC CONFIGURATION FIELDS
    # =========================================================================

    # Core Security - Generic
    auth_secret: SecretStr = Field(
        default=SecretStr(FlextAuthConstants.SECRET_KEY_DEFAULT),
        description="Generic secret key for cryptographic operations",
    )
    algorithm: str = Field(
        default=FlextAuthConstants.ALGORITHM_DEFAULT,
        description="Cryptographic algorithm",
    )
    expiry_minutes: int = Field(
        default=FlextAuthConstants.EXPIRY_MINUTES_DEFAULT,
        description="Default expiry time in minutes",
        ge=1,
        le=FlextAuthConstants.EXPIRY_MAX_MINUTES,
    )
    issuer: str = Field(default="flext-auth", description="Token issuer identifier")
    audience: str = Field(
        default="flext-users", description="Token audience identifier"
    )

    # Credential Processing - Generic
    hash_rounds: int = Field(
        default=FlextAuthConstants.HASH_ROUNDS_DEFAULT,
        description="Rounds for credential hashing",
        ge=FlextAuthConstants.HASH_ROUNDS_MIN,
        le=FlextAuthConstants.HASH_ROUNDS_MAX,
    )
    min_credential_length: int = Field(
        default=FlextAuthConstants.CREDENTIAL_MIN_LENGTH,
        description="Minimum credential length",
        ge=1,
    )
    max_credential_length: int = Field(
        default=FlextAuthConstants.CREDENTIAL_MAX_LENGTH,
        description="Maximum credential length",
        ge=1,
    )

    # Security Policies - Generic
    max_attempts: int = Field(
        default=FlextAuthConstants.MAX_ATTEMPTS_DEFAULT,
        description="Maximum attempts before lockout",
        ge=1,
    )
    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.LOCKOUT_DURATION_MINUTES,
        description="Lockout duration in minutes",
        ge=1,
    )

    # Session Management - Generic
    session_expiry_minutes: int = Field(
        default=FlextAuthConstants.SESSION_EXPIRY_MINUTES_DEFAULT,
        description="Session expiry in minutes",
        ge=1,
        le=FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES,
    )
    max_sessions_per_identity: int = Field(
        default=FlextAuthConstants.MAX_SESSIONS_PER_IDENTITY,
        description="Maximum concurrent sessions per identity",
        ge=1,
    )

    # Audit & Logging - Generic
    enable_audit_logging: bool = Field(
        default=FlextAuthConstants.ENABLE_AUDIT_LOGGING,
        description="Enable audit logging",
    )
    log_attempts: bool = Field(
        default=FlextAuthConstants.LOG_ATTEMPTS,
        description="Log authentication attempts",
    )
    log_failures: bool = Field(
        default=FlextAuthConstants.LOG_FAILURES, description="Log failures"
    )
    log_success: bool = Field(
        default=FlextAuthConstants.LOG_SUCCESS, description="Log successful operations"
    )
    mask_credentials: bool = Field(
        default=FlextAuthConstants.MASK_CREDENTIALS,
        description="Mask credentials in logs",
    )
    mask_tokens: bool = Field(
        default=FlextAuthConstants.MASK_TOKENS, description="Mask tokens in logs"
    )

    # Performance & Rate Limiting - Generic
    track_performance: bool = Field(
        default=FlextAuthConstants.TRACK_PERFORMANCE,
        description="Track performance metrics",
    )
    performance_warning_threshold: float = Field(
        default=FlextAuthConstants.PERFORMANCE_WARNING_THRESHOLD,
        description="Performance warning threshold in milliseconds",
        ge=0.0,
    )
    enable_rate_limiting: bool = Field(
        default=FlextAuthConstants.ENABLE_RATE_LIMITING,
        description="Enable rate limiting",
    )
    max_requests_per_minute: int = Field(
        default=FlextAuthConstants.MAX_REQUESTS_PER_MINUTE,
        description="Maximum requests per minute",
        ge=1,
    )
    max_requests_per_hour: int = Field(
        default=FlextAuthConstants.MAX_REQUESTS_PER_HOUR,
        description="Maximum requests per hour",
        ge=1,
    )

    # Advanced Features - Generic
    require_complexity: bool = Field(
        default=FlextAuthConstants.REQUIRE_COMPLEXITY,
        description="Require complexity validation",
    )
    min_score: int = Field(
        default=FlextAuthConstants.CREDENTIAL_MIN_SCORE,
        description="Minimum complexity score",
        ge=0,
        le=4,
    )
    enable_verification: bool = Field(
        default=FlextAuthConstants.ENABLE_VERIFICATION,
        description="Enable verification process",
    )
    enable_history: bool = Field(
        default=FlextAuthConstants.ENABLE_HISTORY, description="Enable history tracking"
    )

    # =========================================================================
    # METHODS WITH SOLID PRINCIPLES
    # =========================================================================

    def to_dict(self) -> dict[str, object]:
        """Generic serialization with security masking."""
        return {
            "auth_secret": "***masked***" if self.auth_secret else None,
            "algorithm": self.algorithm,
            "expiry_minutes": self.expiry_minutes,
            "issuer": self.issuer,
            "audience": self.audience,
            "hash_rounds": self.hash_rounds,
            "min_credential_length": self.min_credential_length,
            "max_credential_length": self.max_credential_length,
            "max_attempts": self.max_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "session_expiry_minutes": self.session_expiry_minutes,
            "max_sessions_per_identity": self.max_sessions_per_identity,
            "enable_audit_logging": self.enable_audit_logging,
            "log_attempts": self.log_attempts,
            "log_failures": self.log_failures,
            "log_success": self.log_success,
            "mask_credentials": self.mask_credentials,
            "mask_tokens": self.mask_tokens,
            "track_performance": self.track_performance,
            "performance_warning_threshold": self.performance_warning_threshold,
            "enable_rate_limiting": self.enable_rate_limiting,
            "require_complexity": self.require_complexity,
            "min_score": self.min_score,
            "max_requests_per_minute": self.max_requests_per_minute,
            "max_requests_per_hour": self.max_requests_per_hour,
            "enable_verification": self.enable_verification,
            "enable_history": self.enable_history,
        }

    @model_validator(mode="after")
    def validate_configuration(self) -> Self:
        """Generic validation with security checks."""
        # Security validations
        if (
            len(self.auth_secret.get_secret_value())
            < FlextAuthConstants.SECRET_MIN_LENGTH
        ):
            msg = f"Secret key must be at least {FlextAuthConstants.SECRET_MIN_LENGTH} characters long"
            raise ValueError(msg)

        # Boundary validations
        if self.min_credential_length > self.max_credential_length:
            msg = "Minimum credential length cannot exceed maximum credential length"
            raise ValueError(msg)

        if self.session_expiry_minutes > FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES:
            msg = f"Session expiry cannot exceed {FlextAuthConstants.SESSION_EXPIRY_MAX_MINUTES} minutes"
            raise ValueError(msg)

        if self.max_attempts > FlextAuthConstants.MAX_ATTEMPTS_DEFAULT:
            msg = f"Maximum attempts cannot exceed {FlextAuthConstants.MAX_ATTEMPTS_DEFAULT}"
            raise ValueError(msg)

        # Rate limiting validations
        if self.max_requests_per_minute > FlextAuthConstants.MAX_REQUESTS_PER_MINUTE:
            msg = f"Maximum requests per minute cannot exceed {FlextAuthConstants.MAX_REQUESTS_PER_MINUTE}"
            raise ValueError(msg)

        if self.max_requests_per_hour > FlextAuthConstants.MAX_REQUESTS_PER_HOUR:
            msg = f"Maximum requests per hour cannot exceed {FlextAuthConstants.MAX_REQUESTS_PER_HOUR}"
            raise ValueError(msg)

        return self

    @classmethod
    def create(cls, **kwargs: object) -> Self:
        """Factory method for configuration creation."""
        return cls(**kwargs)


__all__ = ["FlextAuthConfig"]

"""FLEXT Auth Configuration - Single unified class following FLEXT standards.

Provides unified configuration management for the FLEXT Auth ecosystem
using Pydantic Settings for environment variable support.
Single FlextAuthConfig class extending FlextConfig with all defaults from FlextAuthConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import (
    FlextConfig,
)
from pydantic import (
    Field,
    SecretStr,
    model_validator,
)

from flext_auth.constants import FlextAuthConstants


class FlextAuthConfig(FlextConfig):
    """Configuration class for FLEXT Authentication service.

    Provides comprehensive authentication configuration with security-focused defaults.
    All settings are environment-configurable for production deployment flexibility.
    """

    # JWT Configuration
    jwt_auth_secret: SecretStr = Field(
        default=SecretStr(FlextAuthConstants.Jwt.SECRET_KEY),
        description="JWT secret key for token signing and validation",
    )
    jwt_algorithm: str = Field(
        default=FlextAuthConstants.Jwt.DEFAULT_ALGORITHM,
        description="JWT algorithm for token signing",
    )
    jwt_expiry_minutes: int = Field(
        default=FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES,
        description="Default JWT token expiry in minutes",
        ge=1,
        le=FlextAuthConstants.Jwt.MAX_EXPIRY_MINUTES,
    )
    jwt_issuer: str = Field(
        default=FlextAuthConstants.Jwt.ISSUER_CLAIM,
        description="JWT issuer claim",
    )
    jwt_audience: str = Field(
        default=FlextAuthConstants.Jwt.AUDIENCE_CLAIM,
        description="JWT audience claim",
    )

    # Password Security
    bcrypt_rounds: int = Field(
        default=FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS,
        description="BCrypt rounds for password hashing",
        ge=FlextAuthConstants.Credentials.Password.MIN_BCRYPT_ROUNDS,
        le=FlextAuthConstants.Credentials.Password.MAX_BCRYPT_ROUNDS,
    )
    min_password_length: int = Field(
        default=FlextAuthConstants.Credentials.Password.MIN_LENGTH,
        description="Minimum password length",
        ge=1,
    )
    max_password_length: int = Field(
        default=FlextAuthConstants.Credentials.Password.MAX_LENGTH,
        description="Maximum password length",
        ge=1,
    )

    # Login Security
    max_login_attempts: int = Field(
        default=FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS,
        description="Maximum login attempts before account lockout",
        ge=1,
    )
    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.Security.LOCKOUT_DURATION_MINUTES,
        description="Account lockout duration in minutes",
        ge=1,
    )

    # Session Management
    session_expiry_minutes: int = Field(
        default=FlextAuthConstants.Session.DEFAULT_EXPIRY_MINUTES,
        description="Default session expiry in minutes",
        ge=1,
        le=FlextAuthConstants.Session.MAX_EXPIRY_MINUTES,
    )
    max_sessions_per_user: int = Field(
        default=FlextAuthConstants.Session.MAX_SESSIONS_PER_USER,
        description="Maximum concurrent sessions per user",
        ge=1,
    )

    # Audit Logging
    enable_audit_logging: bool = Field(
        default=FlextAuthConstants.AuthLogging.Audit.ENABLE_AUDIT_LOGGING,
        description="Enable authentication audit logging",
    )
    log_auth_attempts: bool = Field(
        default=FlextAuthConstants.AuthLogging.Audit.LOG_AUTH_ATTEMPTS,
        description="Log authentication attempts",
    )
    log_auth_failures: bool = Field(
        default=FlextAuthConstants.AuthLogging.Audit.LOG_AUTH_FAILURES,
        description="Log authentication failures",
    )
    log_auth_success: bool = Field(
        default=FlextAuthConstants.AuthLogging.Audit.LOG_AUTH_SUCCESS,
        description="Log successful authentications",
    )

    # Security Logging
    mask_passwords: bool = Field(
        default=FlextAuthConstants.AuthLogging.Security.MASK_PASSWORDS,
        description="Mask passwords in logs",
    )
    mask_tokens: bool = Field(
        default=FlextAuthConstants.AuthLogging.Security.MASK_TOKENS,
        description="Mask tokens in logs",
    )

    # Performance Monitoring
    track_auth_performance: bool = Field(
        default=FlextAuthConstants.AuthLogging.Performance.TRACK_AUTH_PERFORMANCE,
        description="Track authentication performance",
    )
    auth_performance_threshold_warning: float = Field(
        default=FlextAuthConstants.AuthLogging.Performance.THRESHOLD_WARNING,
        description="Performance warning threshold in milliseconds",
        ge=0.0,
    )

    # Rate Limiting
    enable_rate_limiting: bool = Field(
        default=True,
        description="Enable rate limiting for authentication endpoints",
    )
    session_cleanup_interval_minutes: int = Field(
        default=FlextAuthConstants.Session.CLEANUP_INTERVAL_MINUTES,
        description="Session cleanup interval in minutes",
        ge=1,
    )

    # Password Policy
    require_password_complexity: bool = Field(
        default=True,
        description="Require password complexity validation",
    )
    min_password_score: int = Field(
        default=FlextAuthConstants.Credentials.Password.MIN_SCORE,
        description="Minimum password complexity score",
        ge=0,
        le=4,
    )

    # Request Limits
    max_requests_per_minute: int = Field(
        default=FlextAuthConstants.Security.MAX_REQUESTS_PER_MINUTE,
        description="Maximum requests per minute per IP",
        ge=1,
    )
    max_requests_per_hour: int = Field(
        default=FlextAuthConstants.Security.MAX_REQUESTS_PER_HOUR,
        description="Maximum requests per hour per IP",
        ge=1,
    )

    # Feature Flags
    enable_email_verification: bool = Field(
        default=False,
        description="Enable email verification for new accounts",
    )
    enable_password_history: bool = Field(
        default=False,
        description="Enable password history to prevent reuse",
    )

    class Config:
        """Pydantic configuration for FlextAuthConfig."""

        env_prefix = "FLEXT_AUTH_"
        case_sensitive = False
        validate_assignment = True

    def to_dict(self) -> FlextTypes.Dict:
        """Convert configuration to dictionary for serialization."""
        return {
            "jwt_auth_secret": "***masked***" if self.jwt_auth_secret else None,
            "jwt_algorithm": self.jwt_algorithm,
            "jwt_expiry_minutes": self.jwt_expiry_minutes,
            "jwt_issuer": self.jwt_issuer,
            "jwt_audience": self.jwt_audience,
            "bcrypt_rounds": self.bcrypt_rounds,
            "min_password_length": self.min_password_length,
            "max_password_length": self.max_password_length,
            "max_login_attempts": self.max_login_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "session_expiry_minutes": self.session_expiry_minutes,
            "max_sessions_per_user": self.max_sessions_per_user,
            "enable_audit_logging": self.enable_audit_logging,
            "log_auth_attempts": self.log_auth_attempts,
            "log_auth_failures": self.log_auth_failures,
            "log_auth_success": self.log_auth_success,
            "mask_passwords": self.mask_passwords,
            "mask_tokens": self.mask_tokens,
            "track_auth_performance": self.track_auth_performance,
            "auth_performance_threshold_warning": self.auth_performance_threshold_warning,
            "enable_rate_limiting": self.enable_rate_limiting,
            "session_cleanup_interval_minutes": self.session_cleanup_interval_minutes,
            "require_password_complexity": self.require_password_complexity,
            "min_password_score": self.min_password_score,
            "max_requests_per_minute": self.max_requests_per_minute,
            "max_requests_per_hour": self.max_requests_per_hour,
            "enable_email_verification": self.enable_email_verification,
            "enable_password_history": self.enable_password_history,
        }

    @model_validator(mode="after")
    def validate_configuration(self) -> FlextAuthConfig:
        """Validate configuration consistency and security requirements."""
        # Validate JWT secret key length
        if (
            len(self.jwt_auth_secret.get_secret_value())
            < FlextAuthConstants.Jwt.MIN_SECRET_KEY_LENGTH
        ):
            msg = f"JWT secret key must be at least {FlextAuthConstants.Jwt.MIN_SECRET_KEY_LENGTH} characters long"
            raise ValueError(msg)

        # Validate password length bounds
        if self.min_password_length > self.max_password_length:
            msg = "Minimum password length cannot exceed maximum password length"
            raise ValueError(msg)

        # Validate session expiry bounds
        if self.session_expiry_minutes > FlextAuthConstants.Session.MAX_EXPIRY_MINUTES:
            msg = f"Session expiry cannot exceed {FlextAuthConstants.Session.MAX_EXPIRY_MINUTES} minutes"
            raise ValueError(msg)

        # Validate login attempts
        if self.max_login_attempts > FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS:
            msg = f"Maximum login attempts cannot exceed {FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS}"
            raise ValueError(msg)

        # Validate request limits
        if (
            self.max_requests_per_minute
            > FlextAuthConstants.Security.MAX_REQUESTS_PER_MINUTE
        ):
            msg = f"Maximum requests per minute cannot exceed {FlextAuthConstants.Security.MAX_REQUESTS_PER_MINUTE}"
            raise ValueError(msg)

        if (
            self.max_requests_per_hour
            > FlextAuthConstants.Security.MAX_REQUESTS_PER_HOUR
        ):
            msg = f"Maximum requests per hour cannot exceed {FlextAuthConstants.Security.MAX_REQUESTS_PER_HOUR}"
            raise ValueError(msg)

        return self

    @classmethod
    def create(
        cls,
        jwt_auth_secret: str | None = None,
        jwt_algorithm: str | None = None,
        jwt_expiry_minutes: int | None = None,
        jwt_issuer: str | None = None,
        jwt_audience: str | None = None,
        bcrypt_rounds: int | None = None,
        min_password_length: int | None = None,
        max_password_length: int | None = None,
        max_login_attempts: int | None = None,
        lockout_duration_minutes: int | None = None,
        session_expiry_minutes: int | None = None,
        max_sessions_per_user: int | None = None,
        enable_audit_logging: bool | None = None,
        log_auth_attempts: bool | None = None,
        log_auth_failures: bool | None = None,
        log_auth_success: bool | None = None,
        mask_passwords: bool | None = None,
        mask_tokens: bool | None = None,
        track_auth_performance: bool | None = None,
        auth_performance_threshold_warning: float | None = None,
        enable_rate_limiting: bool | None = None,
        session_cleanup_interval_minutes: int | None = None,
        require_password_complexity: bool | None = None,
        min_password_score: int | None = None,
        max_requests_per_minute: int | None = None,
        max_requests_per_hour: int | None = None,
        enable_email_verification: bool | None = None,
        enable_password_history: bool | None = None,
    ) -> FlextAuthConfig:
        """Create a FlextAuthConfig instance with optional overrides."""
        overrides: FlextTypes.Dict = {}

        if jwt_auth_secret is not None:
            overrides["jwt_auth_secret"] = SecretStr(jwt_auth_secret)
        if jwt_algorithm is not None:
            overrides["jwt_algorithm"] = jwt_algorithm
        if jwt_expiry_minutes is not None:
            overrides["jwt_expiry_minutes"] = jwt_expiry_minutes
        if jwt_issuer is not None:
            overrides["jwt_issuer"] = jwt_issuer
        if jwt_audience is not None:
            overrides["jwt_audience"] = jwt_audience
        if bcrypt_rounds is not None:
            overrides["bcrypt_rounds"] = bcrypt_rounds
        if min_password_length is not None:
            overrides["min_password_length"] = min_password_length
        if max_password_length is not None:
            overrides["max_password_length"] = max_password_length
        if max_login_attempts is not None:
            overrides["max_login_attempts"] = max_login_attempts
        if lockout_duration_minutes is not None:
            overrides["lockout_duration_minutes"] = lockout_duration_minutes
        if session_expiry_minutes is not None:
            overrides["session_expiry_minutes"] = session_expiry_minutes
        if max_sessions_per_user is not None:
            overrides["max_sessions_per_user"] = max_sessions_per_user
        if enable_audit_logging is not None:
            overrides["enable_audit_logging"] = enable_audit_logging
        if log_auth_attempts is not None:
            overrides["log_auth_attempts"] = log_auth_attempts
        if log_auth_failures is not None:
            overrides["log_auth_failures"] = log_auth_failures
        if log_auth_success is not None:
            overrides["log_auth_success"] = log_auth_success
        if mask_passwords is not None:
            overrides["mask_passwords"] = mask_passwords
        if mask_tokens is not None:
            overrides["mask_tokens"] = mask_tokens
        if track_auth_performance is not None:
            overrides["track_auth_performance"] = track_auth_performance
        if auth_performance_threshold_warning is not None:
            overrides["auth_performance_threshold_warning"] = (
                auth_performance_threshold_warning
            )
        if enable_rate_limiting is not None:
            overrides["enable_rate_limiting"] = enable_rate_limiting
        if session_cleanup_interval_minutes is not None:
            overrides["session_cleanup_interval_minutes"] = (
                session_cleanup_interval_minutes
            )
        if require_password_complexity is not None:
            overrides["require_password_complexity"] = require_password_complexity
        if min_password_score is not None:
            overrides["min_password_score"] = min_password_score
        if max_requests_per_minute is not None:
            overrides["max_requests_per_minute"] = max_requests_per_minute
        if max_requests_per_hour is not None:
            overrides["max_requests_per_hour"] = max_requests_per_hour
        if enable_email_verification is not None:
            overrides["enable_email_verification"] = enable_email_verification
        if enable_password_history is not None:
            overrides["enable_password_history"] = enable_password_history

        return cls(**overrides)


__all__ = [
    "FlextAuthConfig",
]

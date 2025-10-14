"""FLEXT Auth Configuration - Single unified class following FLEXT standards.

Provides unified configuration management for the FLEXT Auth ecosystem
using Pydantic Settings for environment variable support.
Single FlextAuthConfig class extending FlextCore.Config with all defaults from FlextAuthConstants.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import threading
from typing import ClassVar

from dependency_injector import providers
from flext_core import FlextCore
from pydantic import (
    Field,
    SecretStr,
    model_validator,
)
from pydantic_settings import SettingsConfigDict

from flext_auth.constants import FlextAuthConstants


class FlextAuthConfig(FlextCore.Config):
    """Configuration class for FLEXT Authentication service.

    Provides comprehensive authentication configuration with security-focused defaults.
    All settings are environment-configurable for production deployment flexibility.
    Enhanced with dependency injector integration for service registration.
    """

    # Dependency Injection integration (v1.1.0+)
    _di_config_provider: ClassVar[providers.Configuration | None] = None
    _di_provider_lock: ClassVar[threading.Lock] = threading.Lock()

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        case_sensitive=False,
        validate_assignment=True,
        env_file=".env",
        extra="ignore",
        validate_default=True,
    )

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
        default=FlextAuthConstants.AuthSecurity.MAX_LOGIN_ATTEMPTS,
        description="Maximum login attempts before account lockout",
        ge=1,
    )
    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.AuthSecurity.LOCKOUT_DURATION_MINUTES,
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
        default=FlextAuthConstants.AuthDefaults.DEFAULT_ENABLE_RATE_LIMITING,
        description="Enable rate limiting for authentication endpoints",
    )
    session_cleanup_interval_minutes: int = Field(
        default=FlextAuthConstants.Session.CLEANUP_INTERVAL_MINUTES,
        description="Session cleanup interval in minutes",
        ge=1,
    )

    # Password Policy
    require_password_complexity: bool = Field(
        default=FlextAuthConstants.AuthDefaults.DEFAULT_REQUIRE_PASSWORD_COMPLEXITY,
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
        default=FlextAuthConstants.AuthSecurity.MAX_REQUESTS_PER_MINUTE,
        description="Maximum requests per minute per IP",
        ge=1,
    )
    max_requests_per_hour: int = Field(
        default=FlextAuthConstants.AuthSecurity.MAX_REQUESTS_PER_HOUR,
        description="Maximum requests per hour per IP",
        ge=1,
    )

    # Feature Flags
    enable_email_verification: bool = Field(
        default=FlextAuthConstants.AuthDefaults.DEFAULT_ENABLE_EMAIL_VERIFICATION,
        description="Enable email verification for new accounts",
    )
    enable_password_history: bool = Field(
        default=FlextAuthConstants.AuthDefaults.DEFAULT_ENABLE_PASSWORD_HISTORY,
        description="Enable password history to prevent reuse",
    )

    def to_dict(self) -> FlextCore.Types.Dict:
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
        if self.max_login_attempts > FlextAuthConstants.AuthSecurity.MAX_LOGIN_ATTEMPTS:
            msg = f"Maximum login attempts cannot exceed {FlextAuthConstants.AuthSecurity.MAX_LOGIN_ATTEMPTS}"
            raise ValueError(msg)

        # Validate request limits
        if (
            self.max_requests_per_minute
            > FlextAuthConstants.AuthSecurity.MAX_REQUESTS_PER_MINUTE
        ):
            msg = f"Maximum requests per minute cannot exceed {FlextAuthConstants.AuthSecurity.MAX_REQUESTS_PER_MINUTE}"
            raise ValueError(msg)

        if (
            self.max_requests_per_hour
            > FlextAuthConstants.AuthSecurity.MAX_REQUESTS_PER_HOUR
        ):
            msg = f"Maximum requests per hour cannot exceed {FlextAuthConstants.AuthSecurity.MAX_REQUESTS_PER_HOUR}"
            raise ValueError(msg)

        return self

    # Class methods for DI integration
    @classmethod
    def get_di_config_provider(cls) -> providers.Configuration:
        """Get the dependency-injector Configuration provider."""
        if cls._di_config_provider is None:
            with cls._di_provider_lock:
                if cls._di_config_provider is None:
                    cls._di_config_provider = providers.Configuration()
                    instance = cls._instances.get(cls)
                    if instance is not None:
                        config_dict = instance.model_dump()
                        cls._di_config_provider.from_dict(config_dict)
        return cls._di_config_provider

    @classmethod
    def create(cls, **kwargs: object) -> FlextAuthConfig:
        """Create a new FlextAuthConfig instance with optional overrides."""
        return cls(**kwargs)


__all__ = [
    "FlextAuthConfig",
]

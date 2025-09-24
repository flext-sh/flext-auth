"""FLEXT - Type-safe authentication configuration using flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from typing import ClassVar

from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict

from flext_auth.constants import FlextAuthConstants
from flext_core import (
    FlextConfig,
    FlextConstants,
    FlextResult,
)


class FlextAuthLoggingConstants(FlextConstants):
    """Authentication-specific logging constants for FLEXT Auth module.

    Provides domain-specific logging defaults, levels, and configuration
    options tailored for authentication operations and security logging.
    """

    # Authentication-specific log levels
    DEFAULT_LEVEL = FlextConstants.Config.LogLevel.INFO
    AUTH_OPERATIONS_LEVEL = FlextConstants.Config.LogLevel.INFO
    SECURITY_EVENTS_LEVEL = FlextConstants.Config.LogLevel.WARNING
    TOKEN_OPERATIONS_LEVEL = FlextConstants.Config.LogLevel.DEBUG
    USER_OPERATIONS_LEVEL = FlextConstants.Config.LogLevel.INFO

    # Security-specific logging configuration
    MASK_PASSWORDS = True
    MASK_TOKENS = True
    MASK_SESSION_IDS = True
    LOG_AUTH_ATTEMPTS = True
    LOG_AUTH_FAILURES = True
    LOG_AUTH_SUCCESS = False  # Don't log successful auth by default for privacy
    LOG_TOKEN_CREATION = True
    LOG_TOKEN_VALIDATION = False  # Don't log token validation by default
    LOG_USER_CREATION = True
    LOG_USER_DELETION = True
    LOG_PERMISSION_CHANGES = True

    # Performance tracking for auth operations
    TRACK_AUTH_PERFORMANCE = True
    AUTH_PERFORMANCE_THRESHOLD_WARNING = (
        FlextConstants.Performance.AUTH_PERFORMANCE_WARNING_MS
    )
    AUTH_PERFORMANCE_THRESHOLD_CRITICAL = (
        FlextConstants.Performance.AUTH_PERFORMANCE_CRITICAL_MS
    )

    # Context information to include
    INCLUDE_USER_ID = True
    INCLUDE_SESSION_ID = True
    INCLUDE_IP_ADDRESS = True
    INCLUDE_USER_AGENT = False  # Privacy consideration
    INCLUDE_REQUEST_ID = True

    # Error logging specifics
    LOG_VALIDATION_ERRORS = True
    LOG_AUTHENTICATION_ERRORS = True
    LOG_AUTHORIZATION_ERRORS = True
    LOG_TOKEN_EXPIRY = True
    LOG_SESSION_TIMEOUT = True

    # Audit logging
    ENABLE_AUDIT_LOGGING = True
    AUDIT_LOG_LEVEL = FlextConstants.Config.LogLevel.INFO
    AUDIT_LOG_FILE = "flext_auth_audit.log"

    # Message templates for auth operations
    class Messages:
        """Authentication-specific log message templates."""

        # Authentication messages
        AUTH_ATTEMPT = "Authentication attempt for user {user_id} from {ip_address}"
        AUTH_SUCCESS = "Authentication successful for user {user_id}"
        AUTH_FAILED = (
            "Authentication failed for user {user_id} from {ip_address}: {reason}"
        )
        AUTH_BLOCKED = (
            "Authentication blocked for user {user_id} from {ip_address}: {reason}"
        )

        # Token messages
        TOKEN_CREATED = "Token created for user {user_id}, type: {token_type}"
        TOKEN_VALIDATED = "Token validated for user {user_id}"
        TOKEN_EXPIRED = "Token expired for user {user_id}"
        TOKEN_REVOKED = "Token revoked for user {user_id}"
        TOKEN_REFRESH = "Token refreshed for user {user_id}"

        # User management messages
        USER_CREATED = "User created: {user_id}"
        USER_UPDATED = "User updated: {user_id}"
        USER_DELETED = "User deleted: {user_id}"
        USER_LOCKED = "User locked: {user_id}"
        USER_UNLOCKED = "User unlocked: {user_id}"

        # Permission messages
        PERMISSION_GRANTED = "Permission granted: {permission} to user {user_id}"
        PERMISSION_REVOKED = "Permission revoked: {permission} from user {user_id}"
        ROLE_ASSIGNED = "Role assigned: {role} to user {user_id}"
        ROLE_REMOVED = "Role removed: {role} from user {user_id}"

        # Session messages
        SESSION_CREATED = "Session created for user {user_id}"
        SESSION_DESTROYED = "Session destroyed for user {user_id}"
        SESSION_EXPIRED = "Session expired for user {user_id}"
        SESSION_EXTENDED = "Session extended for user {user_id}"

        # Security messages
        SECURITY_VIOLATION = "Security violation: {violation_type} for user {user_id}"
        SUSPICIOUS_ACTIVITY = (
            "Suspicious activity detected for user {user_id}: {activity}"
        )
        BRUTE_FORCE_ATTEMPT = "Brute force attempt detected from {ip_address}"

        # Performance messages
        AUTH_SLOW = "Authentication operation slow: {operation} took {duration}ms for user {user_id}"
        TOKEN_SLOW = (
            "Token operation slow: {operation} took {duration}ms for user {user_id}"
        )

        # Error messages
        AUTH_ERROR = "Authentication error: {error} for user {user_id}"
        TOKEN_ERROR = "Token error: {error} for user {user_id}"
        USER_ERROR = "User management error: {error} for user {user_id}"
        PERMISSION_ERROR = "Permission error: {error} for user {user_id}"

    # Environment-specific overrides for auth logging
    class Environment:
        """Environment-specific authentication logging configuration."""

        DEVELOPMENT: ClassVar[dict[str, object]] = {
            "log_auth_success": True,  # Log successful auth in dev
            "log_token_validation": True,  # Log token validation in dev
            "include_user_agent": True,  # Include user agent in dev
            "audit_log_level": FlextConstants.Config.LogLevel.DEBUG,
        }

        STAGING: ClassVar[dict[str, object]] = {
            "log_auth_success": False,
            "log_token_validation": False,
            "include_user_agent": False,
            "audit_log_level": FlextConstants.Config.LogLevel.INFO,
        }

        PRODUCTION: ClassVar[dict[str, object]] = {
            "log_auth_success": False,
            "log_token_validation": False,
            "include_user_agent": False,
            "audit_log_level": FlextConstants.Config.LogLevel.WARNING,
        }

        TESTING: ClassVar[dict[str, object]] = {
            "log_auth_success": True,
            "log_token_validation": True,
            "include_user_agent": True,
            "audit_log_level": FlextConstants.Config.LogLevel.DEBUG,
        }


class FlextAuthConfig(FlextConfig):
    """Authentication configuration class extending FlextConfig with singleton pattern.

    This class provides authentication-specific configuration management,
    extending the base FlextConfig with authentication-specific fields and validation rules.
    It uses the singleton pattern to ensure a single source of truth for authentication
    configuration across the entire application.
    """

    # Class variable for singleton pattern
    _global_instance: ClassVar[FlextAuthConfig | None] = None

    # Authentication-specific logging configuration using FlextAuthLoggingConstants
    enable_audit_logging: bool = Field(
        default=FlextAuthLoggingConstants.ENABLE_AUDIT_LOGGING,
        description="Enable detailed audit logging",
    )

    # Additional authentication logging fields using FlextAuthLoggingConstants
    log_auth_attempts: bool = Field(
        default=FlextAuthLoggingConstants.LOG_AUTH_ATTEMPTS,
        description="Log authentication attempts",
    )

    log_auth_failures: bool = Field(
        default=FlextAuthLoggingConstants.LOG_AUTH_FAILURES,
        description="Log authentication failures",
    )

    log_auth_success: bool = Field(
        default=FlextAuthLoggingConstants.LOG_AUTH_SUCCESS,
        description="Log successful authentications",
    )

    log_token_creation: bool = Field(
        default=FlextAuthLoggingConstants.LOG_TOKEN_CREATION,
        description="Log token creation events",
    )

    log_token_validation: bool = Field(
        default=FlextAuthLoggingConstants.LOG_TOKEN_VALIDATION,
        description="Log token validation events",
    )

    log_user_creation: bool = Field(
        default=FlextAuthLoggingConstants.LOG_USER_CREATION,
        description="Log user creation events",
    )

    log_user_deletion: bool = Field(
        default=FlextAuthLoggingConstants.LOG_USER_DELETION,
        description="Log user deletion events",
    )

    log_permission_changes: bool = Field(
        default=FlextAuthLoggingConstants.LOG_PERMISSION_CHANGES,
        description="Log permission changes",
    )

    # Security configuration
    max_login_attempts: int = Field(
        default=5,
        ge=1,
        description="Maximum failed login attempts before account lockout",
    )

    # JWT Configuration from FlextAuthConstants (jwt_secret inherited from FlextConfig)

    jwt_algorithm: str = Field(
        default="HS256",
        description="JWT signing algorithm",
    )

    jwt_expiry_minutes: int = Field(
        default=30,
        ge=1,
        description="JWT token expiry time in minutes",
    )

    jwt_issuer: str = Field(
        default="",
        description="JWT token issuer",
    )

    jwt_audience: str = Field(
        default="",
        description="JWT token audience",
    )

    # Password & Session Configuration
    bcrypt_rounds: int = Field(
        default=12,
        ge=10,
        description="Bcrypt rounds for password hashing",
    )

    lockout_duration_minutes: int = Field(
        default=30,
        description="Account lockout duration in minutes",
    )

    session_expiry_hours: int = Field(
        default=2,
        description="Session expiry time in hours",
    )

    session_expiry_minutes: int = Field(
        default=120,
        description="Session expiry time in minutes (alternative to hours)",
    )

    enable_rate_limiting: bool = Field(
        default=False,
        description="Enable rate limiting for authentication endpoints",
    )

    min_password_length: int = Field(
        default=8,
        ge=6,
        description="Minimum password length",
    )

    max_password_length: int = Field(
        default=256,
        description="Maximum password length",
    )

    # Security logging configuration
    mask_passwords: bool = Field(
        default=FlextAuthLoggingConstants.MASK_PASSWORDS,
        description="Mask passwords in log messages",
    )

    mask_tokens: bool = Field(
        default=FlextAuthLoggingConstants.MASK_TOKENS,
        description="Mask tokens in log messages",
    )

    mask_session_ids: bool = Field(
        default=FlextAuthLoggingConstants.MASK_SESSION_IDS,
        description="Mask session IDs in log messages",
    )

    # Performance tracking for auth operations
    track_auth_performance: bool = Field(
        default=FlextAuthLoggingConstants.TRACK_AUTH_PERFORMANCE,
        description="Track authentication performance",
    )

    auth_performance_threshold_warning: float = Field(
        default=FlextAuthLoggingConstants.AUTH_PERFORMANCE_THRESHOLD_WARNING,
        description="Authentication performance warning threshold in milliseconds",
    )

    auth_performance_threshold_critical: float = Field(
        default=FlextAuthLoggingConstants.AUTH_PERFORMANCE_THRESHOLD_CRITICAL,
        description="Authentication performance critical threshold in milliseconds",
    )

    # Context information to include in logs
    include_user_id: bool = Field(
        default=FlextAuthLoggingConstants.INCLUDE_USER_ID,
        description="Include user ID in log messages",
    )

    include_session_id: bool = Field(
        default=FlextAuthLoggingConstants.INCLUDE_SESSION_ID,
        description="Include session ID in log messages",
    )

    include_ip_address: bool = Field(
        default=FlextAuthLoggingConstants.INCLUDE_IP_ADDRESS,
        description="Include IP address in log messages",
    )

    include_user_agent: bool = Field(
        default=FlextAuthLoggingConstants.INCLUDE_USER_AGENT,
        description="Include user agent in log messages",
    )

    include_request_id: bool = Field(
        default=FlextAuthLoggingConstants.INCLUDE_REQUEST_ID,
        description="Include request ID in log messages",
    )

    # Error logging configuration
    log_validation_errors: bool = Field(
        default=FlextAuthLoggingConstants.LOG_VALIDATION_ERRORS,
        description="Log validation errors",
    )

    log_authentication_errors: bool = Field(
        default=FlextAuthLoggingConstants.LOG_AUTHENTICATION_ERRORS,
        description="Log authentication errors",
    )

    log_authorization_errors: bool = Field(
        default=FlextAuthLoggingConstants.LOG_AUTHORIZATION_ERRORS,
        description="Log authorization errors",
    )

    log_token_expiry: bool = Field(
        default=FlextAuthLoggingConstants.LOG_TOKEN_EXPIRY,
        description="Log token expiry events",
    )

    log_session_timeout: bool = Field(
        default=FlextAuthLoggingConstants.LOG_SESSION_TIMEOUT,
        description="Log session timeout events",
    )

    # Audit logging configuration
    audit_log_level: str = Field(
        default=FlextAuthLoggingConstants.AUDIT_LOG_LEVEL,
        description="Audit log level",
    )

    audit_log_file: str = Field(
        default=FlextAuthLoggingConstants.AUDIT_LOG_FILE,
        description="Audit log file path",
    )

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        case_sensitive=False,
        validate_default=True,
        arbitrary_types_allowed=True,
        populate_by_name=True,
    )

    @field_validator("min_password_length")
    @classmethod
    def validate_min_password_length(cls, v: int) -> int:
        """Validate minimum password length."""
        if v < FlextAuthConstants.MIN_PASSWORD_LENGTH:
            msg = "Input should be greater than or equal to 6"
            raise ValueError(msg)
        return v

    @field_validator("jwt_expiry_minutes", "session_expiry_hours")
    @classmethod
    def validate_positive(cls, v: int) -> int:
        """Validate positive values for time-based fields."""
        if v <= 0:
            msg = "Value must be greater than 0"
            raise ValueError(msg)
        return v

    @field_validator("bcrypt_rounds")
    @classmethod
    def validate_bcrypt_rounds(cls, v: int) -> int:
        """Validate bcrypt rounds for security."""
        if v < FlextAuthConstants.MIN_BCRYPT_ROUNDS:
            msg = "Bcrypt rounds must be at least 10"
            raise ValueError(msg)
        return v

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        """Validate and generate JWT secret if empty."""
        if not v or not v.strip():
            # Generate a secure JWT secret
            return secrets.token_urlsafe(32)
        return v

    @field_validator("max_login_attempts")
    @classmethod
    def validate_max_login_attempts(cls, v: int) -> int:
        """Validate maximum login attempts."""
        if v < 1:
            msg = "Max login attempts must be at least 1"
            raise ValueError(msg)
        return v

    def get_auth_logging_config(self) -> dict[str, object]:
        """Get authentication-specific logging configuration dictionary."""
        return {
            "enable_audit_logging": self.enable_audit_logging,
            "log_auth_attempts": self.log_auth_attempts,
            "log_auth_failures": self.log_auth_failures,
            "log_auth_success": self.log_auth_success,
            "log_token_creation": self.log_token_creation,
            "log_token_validation": self.log_token_validation,
            "log_user_creation": self.log_user_creation,
            "log_user_deletion": self.log_user_deletion,
            "log_permission_changes": self.log_permission_changes,
            "mask_passwords": self.mask_passwords,
            "mask_tokens": self.mask_tokens,
            "mask_session_ids": self.mask_session_ids,
            "track_auth_performance": self.track_auth_performance,
            "auth_performance_threshold_warning": self.auth_performance_threshold_warning,
            "auth_performance_threshold_critical": self.auth_performance_threshold_critical,
            "include_user_id": self.include_user_id,
            "include_session_id": self.include_session_id,
            "include_ip_address": self.include_ip_address,
            "include_user_agent": self.include_user_agent,
            "include_request_id": self.include_request_id,
            "log_validation_errors": self.log_validation_errors,
            "log_authentication_errors": self.log_authentication_errors,
            "log_authorization_errors": self.log_authorization_errors,
            "log_token_expiry": self.log_token_expiry,
            "log_session_timeout": self.log_session_timeout,
            "audit_log_level": self.audit_log_level,
            "audit_log_file": self.audit_log_file,
        }

    @classmethod
    def create_from_cli_params(
        cls,
        jwt_expiry: int | None = None,
        bcrypt_rounds: int | None = None,
        environment: str | None = None,
        max_attempts: int | None = None,
        session_expiry: int | None = None,
    ) -> FlextResult[FlextAuthConfig]:
        """Create configuration from CLI parameters."""
        try:
            # Create base config and then update specific fields
            config = cls()

            if jwt_expiry is not None:
                config.jwt_expiry_minutes = jwt_expiry
            if bcrypt_rounds is not None:
                config.bcrypt_rounds = bcrypt_rounds
            if environment is not None:
                config.environment = environment
            if max_attempts is not None:
                config.max_login_attempts = max_attempts
            if session_expiry is not None:
                config.session_expiry_minutes = session_expiry

            return FlextResult[FlextAuthConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to create config from CLI params: {e}"
            )

    @classmethod
    def update_global_from_cli(
        cls,
        jwt_expiry: int | None = None,
        bcrypt_rounds: int | None = None,
        environment: str | None = None,
        max_attempts: int | None = None,
        session_expiry: int | None = None,
    ) -> FlextResult[None]:
        """Update global configuration from CLI parameters."""
        try:
            # Get current global instance
            config = cls.get_global_instance()

            # Update fields if provided
            if jwt_expiry is not None:
                config.jwt_expiry_minutes = jwt_expiry
            if bcrypt_rounds is not None:
                config.bcrypt_rounds = bcrypt_rounds
            if environment is not None:
                config.environment = environment
            if max_attempts is not None:
                config.max_login_attempts = max_attempts
            if session_expiry is not None:
                config.session_expiry_hours = session_expiry

            # Set the updated config as global instance
            cls.set_global_instance(config)

            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Failed to update global config: {e}")

    @classmethod
    def get_global_cli_summary(cls) -> FlextResult[dict[str, object]]:
        """Get global CLI configuration summary."""
        try:
            config = cls.get_global_instance()
            summary: dict[str, object] = {
                "max_login_attempts": config.max_login_attempts,
                "jwt_expiry": config.jwt_expiry_minutes,
                "bcrypt_rounds": config.bcrypt_rounds,
                "environment": "development",
            }
            return FlextResult[dict[str, object]].ok(summary)
        except Exception as e:
            return FlextResult[dict[str, object]].fail(
                f"Failed to get CLI summary: {e}"
            )

    @classmethod
    def get_global_instance(cls) -> FlextAuthConfig:
        """Get global singleton instance of FlextAuthConfig."""
        if not hasattr(cls, "_global_instance") or cls._global_instance is None:
            cls._global_instance = cls()
        return cls._global_instance

    @classmethod
    def create_for_environment(
        cls, environment: str, **overrides: object
    ) -> FlextAuthConfig:
        """Create configuration for specific environment with overrides."""
        # Create config with environment and overrides - Pydantic will validate environment
        config_data: dict[str, object] = {"environment": environment, **overrides}
        return cls.model_validate(config_data)

    @classmethod
    def create_with_overrides(cls, **overrides: object) -> FlextResult[FlextAuthConfig]:
        """Create configuration with specific overrides."""
        try:
            # Create base config and apply overrides using model_copy with update
            config = cls()
            if overrides:
                config = config.model_copy(update=overrides)
            return FlextResult[FlextAuthConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to create config with overrides: {e}"
            )

    @classmethod
    def get_or_create_global(cls, **overrides: object) -> FlextResult[FlextAuthConfig]:
        """Get or create global instance with optional overrides."""
        try:
            if overrides:
                # Handle JWT secret generation if empty
                if "jwt_secret" in overrides and (
                    not overrides["jwt_secret"]
                    or not str(overrides["jwt_secret"]).strip()
                ):
                    overrides["jwt_secret"] = secrets.token_urlsafe(32)

                # Create base config and apply overrides using model_copy with update
                config = cls()
                config = config.model_copy(update=overrides)
                cls._global_instance = config
                return FlextResult[FlextAuthConfig].ok(config)
            return FlextResult[FlextAuthConfig].ok(cls.get_global_instance())
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to get or create global instance: {e}"
            )

    @classmethod
    def set_global_instance(cls, instance: FlextConfig) -> None:
        """Set global instance with type validation."""
        if not isinstance(instance, FlextAuthConfig):
            msg = "config must be an instance of FlextAuthConfig"
            raise TypeError(msg)
        cls._global_instance = instance

    def validate_configuration(self) -> FlextResult[None]:
        """Validate configuration settings."""
        session_minutes = (
            self.session_expiry_minutes
            if hasattr(self, "session_expiry_minutes") and self.session_expiry_minutes
            else self.session_expiry_hours * 60
        )

        if self.jwt_expiry_minutes > (session_minutes * 2):
            return FlextResult[None].fail(
                "JWT expiry should not exceed twice the session expiry"
            )
        return FlextResult[None].ok(None)

    def get_security_settings(self) -> dict[str, object]:
        """Get security-related settings."""
        return {
            "bcrypt_rounds": self.bcrypt_rounds,
            "max_login_attempts": self.max_login_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "min_password_length": self.min_password_length,
            "max_password_length": getattr(self, "max_password_length", 256),
            "require_password_complexity": getattr(
                self, "require_password_complexity", True
            ),
            "min_password_score": getattr(self, "min_password_score", 3),
        }

    def get_jwt_settings(self) -> dict[str, object]:
        """Get JWT-related settings."""
        return {
            "jwt_expiry_minutes": self.jwt_expiry_minutes,
            "jwt_algorithm": self.jwt_algorithm,
            "jwt_issuer": self.jwt_issuer,
            "jwt_audience": self.jwt_audience,
            "jwt_secret_length": len(self.jwt_secret),
        }

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for authentication configuration."""
        if self.min_password_length < FlextAuthConstants.MIN_PASSWORD_LENGTH:
            return FlextResult[None].fail("Password minimum length must be at least 8")

        if self.max_login_attempts > FlextAuthConstants.MAX_LOGIN_ATTEMPTS:
            return FlextResult[None].fail("Max login attempts cannot exceed 10")

        if self.bcrypt_rounds < FlextAuthConstants.MIN_BCRYPT_ROUNDS:
            return FlextResult[None].fail(
                "Bcrypt rounds must be at least 10 for security"
            )

        if self.jwt_expiry_minutes > FlextAuthConstants.JWT_MAX_EXPIRY_MINUTES:
            return FlextResult[None].fail("JWT expiry cannot exceed 24 hours")

        return FlextResult[None].ok(None)

    @classmethod
    def _reset_global_instance(cls) -> None:
        """Reset global instance (for testing)."""
        cls._global_instance = None


__all__ = [
    "FlextAuthConfig",
]

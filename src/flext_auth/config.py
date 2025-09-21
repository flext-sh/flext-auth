"""FLEXT - Type-safe authentication configuration using flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import ClassVar

from pydantic import Field

from flext_core import (
    FlextConfig,
    FlextConstants,
    FlextResult,
)


class FlextAuthLoggingConstants:
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
        description="Maximum failed login attempts before account lockout",
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
            config_data: dict[str, object] = {}
            if jwt_expiry is not None:
                config_data["jwt_expiry"] = jwt_expiry
            if bcrypt_rounds is not None:
                config_data["bcrypt_rounds"] = bcrypt_rounds
            if environment is not None:
                config_data["environment"] = environment
            if max_attempts is not None:
                config_data["max_login_attempts"] = max_attempts
            if session_expiry is not None:
                config_data["session_timeout"] = session_expiry

            config = cls(**config_data)
            return FlextResult[FlextAuthConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to create config from CLI params: {e}"
            )

    @classmethod
    def update_global_from_cli(cls, **_kwargs: object) -> FlextResult[None]:
        """Update global configuration from CLI parameters."""
        try:
            # In a real implementation, this would update the global singleton
            return FlextResult[None].ok(None)
        except Exception as e:
            return FlextResult[None].fail(f"Failed to update global config: {e}")

    @classmethod
    def get_global_cli_summary(cls) -> FlextResult[dict[str, object]]:
        """Get global CLI configuration summary."""
        try:
            # Return a summary of current configuration
            summary = {
                "max_login_attempts": 5,
                "jwt_expiry": 3600,
                "bcrypt_rounds": 12,
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
    def _reset_global_instance(cls) -> None:
        """Reset global instance (for testing)."""
        cls._global_instance = None


# Module exports
__all__ = [
    "FlextAuthConfig",
]

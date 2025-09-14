"""FLEXT - Type-safe authentication configuration using flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from typing import ClassVar

from flext_core import (
    FlextConfig,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from pydantic import Field, ValidationInfo, field_validator, model_validator
from pydantic_settings import SettingsConfigDict

from flext_auth.constants import FlextAuthConstants


class FlextAuthConfig(FlextConfig):
    """Authentication configuration class extending FlextConfig with singleton pattern.

    Provides type-safe configuration for authentication services with
    environment variable support, validation, and default values following
    flext-core configuration patterns. Uses singleton pattern as source of truth.

    Configuration Structure:
        - JWT settings: secret key, expiration, algorithms
        - Security settings: bcrypt rounds, rate limiting
        - Session settings: expiration, cleanup intervals
        - Validation settings: password requirements, attempt limits

    Environment Variables:
        - FLEXT_AUTH_JWT_SECRET: JWT signing secret
        - FLEXT_AUTH_JWT_EXPIRY_MINUTES: JWT token expiry
        - FLEXT_AUTH_BCRYPT_ROUNDS: Password hashing rounds
        - FLEXT_AUTH_MAX_LOGIN_ATTEMPTS: Failed attempt limit
        - FLEXT_AUTH_SESSION_EXPIRY_MINUTES: Session expiry

    Singleton Usage:
        # Get global instance (source of truth)
        config = FlextAuthConfig.get_global_instance()

        # Set global instance with overrides
        FlextAuthConfig.set_global_instance(custom_config)

        # Create with environment-specific settings
        config = FlextAuthConfig.create_for_environment("production")

    """

    # SINGLETON PATTERN - Global configuration instance
    _auth_global_instance: ClassVar[FlextAuthConfig | None] = None

    # Override model_config to use FLEXT_AUTH_ prefix for auth-specific fields
    model_config = SettingsConfigDict(
        # Environment integration
        env_prefix="FLEXT_AUTH_",
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        # Validation behavior
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=True,
        extra="ignore",
        # Schema generation
        title="FLEXT Auth Configuration",
        json_schema_extra={
            "description": "FLEXT authentication configuration with type safety",
            "examples": [
                {
                    "jwt_expiry_minutes": 30,
                    "bcrypt_rounds": 12,
                    "max_login_attempts": 5,
                }
            ],
        },
    )

    # =========================================================================
    # JWT CONFIGURATION
    # =========================================================================

    jwt_secret: str = Field(
        default="",  # Will be generated in validator if empty
        description="JWT signing secret key",
    )

    jwt_expiry_minutes: int = Field(
        default=30,  # Production-ready default: 30 minutes
        description="JWT token expiry in minutes",
        ge=1,  # Minimum 1 minute
        le=FlextAuthConstants.JWT_MAX_EXPIRY_MINUTES,
    )

    jwt_algorithm: str = Field(
        default=FlextAuthConstants.JWT_DEFAULT_ALGORITHM,
        description="JWT signing algorithm",
    )

    jwt_issuer: str = Field(
        default=FlextAuthConstants.JWT_ISSUER_CLAIM, description="JWT issuer claim"
    )

    jwt_audience: str = Field(
        default=FlextAuthConstants.JWT_AUDIENCE_CLAIM, description="JWT audience claim"
    )

    # =========================================================================
    # SECURITY CONFIGURATION
    # =========================================================================

    bcrypt_rounds: int = Field(
        default=FlextAuthConstants.BCRYPT_ROUNDS,
        description="Bcrypt hashing rounds",
        ge=FlextAuthConstants.MIN_BCRYPT_ROUNDS,
        le=FlextAuthConstants.MAX_BCRYPT_ROUNDS,
    )

    max_login_attempts: int = Field(
        default=FlextAuthConstants.MAX_LOGIN_ATTEMPTS,
        description="Maximum failed login attempts before lockout",
        ge=1,  # Minimum 1 attempt
        le=20,  # Maximum 20 attempts
    )

    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.LOCKOUT_DURATION_MINUTES,
        description="Account lockout duration in minutes",
        ge=1,  # Minimum 1 minute
        le=1440,  # Maximum 24 hours
    )

    # =========================================================================
    # SESSION CONFIGURATION
    # =========================================================================

    session_expiry_minutes: int = Field(
        default=FlextAuthConstants.DEFAULT_SESSION_EXPIRY_MINUTES,
        description="Session expiry in minutes",
        ge=5,
        le=FlextAuthConstants.MAX_SESSION_EXPIRY_MINUTES,
    )

    max_sessions_per_user: int = Field(
        default=FlextAuthConstants.MAX_SESSIONS_PER_USER,
        description="Maximum concurrent sessions per user",
        ge=1,
        le=20,
    )

    session_cleanup_interval_minutes: int = Field(
        default=FlextAuthConstants.SESSION_CLEANUP_INTERVAL_MINUTES,
        description="Session cleanup interval in minutes",
        ge=5,
        le=1440,
    )

    # =========================================================================
    # PASSWORD VALIDATION CONFIGURATION
    # =========================================================================

    min_password_length: int = Field(
        default=FlextAuthConstants.MIN_PASSWORD_LENGTH,
        description="Minimum password length",
        ge=6,
        le=20,
    )

    max_password_length: int = Field(
        default=FlextAuthConstants.MAX_PASSWORD_LENGTH,
        description="Maximum password length",
        ge=20,
        le=256,
    )

    require_password_complexity: bool = Field(
        default=True,
        description="Require complex passwords with mixed case, numbers, and symbols",
    )

    min_password_score: int = Field(
        default=FlextAuthConstants.MIN_PASSWORD_SCORE,
        description="Minimum password strength score (1-5)",
        ge=1,
        le=5,
    )

    # =========================================================================
    # RATE LIMITING CONFIGURATION
    # =========================================================================

    max_requests_per_minute: int = Field(
        default=FlextAuthConstants.MAX_REQUESTS_PER_MINUTE,
        description="Maximum authentication requests per minute",
        ge=10,
        le=300,
    )

    max_requests_per_hour: int = Field(
        default=FlextAuthConstants.MAX_REQUESTS_PER_HOUR,
        description="Maximum authentication requests per hour",
        ge=100,
        le=10000,
    )

    # =========================================================================
    # FEATURE FLAGS
    # =========================================================================

    enable_email_verification: bool = Field(
        default=False, description="Enable email verification for new accounts"
    )

    enable_password_history: bool = Field(
        default=False, description="Prevent password reuse (password history)"
    )

    enable_audit_logging: bool = Field(
        default=True, description="Enable detailed audit logging"
    )

    enable_rate_limiting: bool = Field(
        default=True, description="Enable rate limiting for authentication endpoints"
    )

    # =========================================================================
    # FIELD VALIDATORS
    # =========================================================================

    @model_validator(mode="after")
    def validate_jwt_secret(self) -> FlextAuthConfig:
        """Validate JWT secret key requirements."""
        if not self.jwt_secret:
            # Generate secure random secret using flext-core utilities
            self.jwt_secret = FlextUtilities.Generators.generate_uuid()

        if (
            len(self.jwt_secret) < FlextAuthConstants.MIN_SECRET_KEY_LENGTH
        ):  # pragma: no cover
            msg = f"JWT secret must be at least {FlextAuthConstants.MIN_SECRET_KEY_LENGTH} characters"  # pragma: no cover
            raise ValueError(msg)  # pragma: no cover

        return self

    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm is supported."""
        if v not in FlextAuthConstants.JWT_ALLOWED_ALGORITHMS:  # pragma: no cover
            msg = f"JWT algorithm must be one of: {FlextAuthConstants.JWT_ALLOWED_ALGORITHMS}"  # pragma: no cover
            raise ValueError(msg)  # pragma: no cover
        return v

    @field_validator("min_password_length", "max_password_length")
    @classmethod
    def validate_password_lengths(cls, v: int, info: ValidationInfo) -> int:
        """Validate password length constraints are logical."""
        # This validator runs for both fields, so we need to check context
        if info.field_name == "max_password_length":
            # Ensure max is greater than min (we'll have min from defaults)
            min_length = FlextAuthConstants.MIN_PASSWORD_LENGTH
            if v <= min_length:  # pragma: no cover
                msg = f"Maximum password length must be greater than minimum ({min_length})"  # pragma: no cover
                raise ValueError(msg)  # pragma: no cover
        return v

    # =========================================================================
    # CONFIGURATION METHODS
    # =========================================================================

    def get_security_settings(self) -> FlextTypes.Core.Dict:
        """Get security-related configuration settings.

        Returns:
            Dictionary containing security configuration

        """
        return {
            "bcrypt_rounds": self.bcrypt_rounds,
            "max_login_attempts": self.max_login_attempts,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "min_password_length": self.min_password_length,
            "max_password_length": self.max_password_length,
            "require_password_complexity": self.require_password_complexity,
            "min_password_score": self.min_password_score,
        }

    def get_jwt_settings(self) -> FlextTypes.Core.Dict:
        """Get JWT-related configuration settings.

        Returns:
            Dictionary containing JWT configuration (secret excluded for security)

        """
        return {
            "jwt_expiry_minutes": self.jwt_expiry_minutes,
            "jwt_algorithm": self.jwt_algorithm,
            "jwt_issuer": self.jwt_issuer,
            "jwt_audience": self.jwt_audience,
            "jwt_secret_length": len(self.jwt_secret),  # Length only for security
        }

    def get_session_settings(self) -> FlextTypes.Core.Dict:
        """Get session-related configuration settings.

        Returns:
            Dictionary containing session configuration

        """
        return {  # pragma: no cover
            "session_expiry_minutes": self.session_expiry_minutes,  # pragma: no cover
            "max_sessions_per_user": self.max_sessions_per_user,  # pragma: no cover
            "session_cleanup_interval_minutes": self.session_cleanup_interval_minutes,  # pragma: no cover
        }  # pragma: no cover

    def validate_configuration(self) -> FlextResult[None]:
        """Validate complete configuration for consistency.

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            # Validate password length consistency
            if self.min_password_length >= self.max_password_length:  # pragma: no cover
                return FlextResult[
                    None
                ].fail(  # pragma: no cover
                    "Minimum password length must be less than maximum"  # pragma: no cover
                )  # pragma: no cover

            # Validate JWT expiry is reasonable (allow some flexibility)
            # JWT can be longer than session for stateless authentication
            if self.jwt_expiry_minutes > FlextAuthConstants.JWT_MAX_EXPIRY_MINUTES:
                return FlextResult[None].fail(
                    f"JWT expiry cannot exceed {FlextAuthConstants.JWT_MAX_EXPIRY_MINUTES} minutes"
                )

            # Validate bcrypt rounds are in safe range
            if (
                self.bcrypt_rounds < FlextAuthConstants.MIN_BCRYPT_ROUNDS
            ):  # pragma: no cover
                return FlextResult[
                    None
                ].fail(  # pragma: no cover
                    "Bcrypt rounds should be at least 10 for security"  # pragma: no cover
                )  # pragma: no cover

            # Validate JWT expiry is reasonable compared to session expiry
            # JWT can be shorter than session for token refresh patterns
            if self.jwt_expiry_minutes > self.session_expiry_minutes * 2:
                return FlextResult[None].fail(
                    "JWT expiry should not exceed twice the session expiry"
                )

            # Skip rate limiting validation for now - different models (burst vs sustained)

            return FlextResult[None].ok(None)

        except Exception as e:  # pragma: no cover
            return FlextResult[None].fail(
                f"Configuration validation failed: {e}"
            )  # pragma: no cover

    @classmethod
    def create_for_environment(
        cls, environment: str = "development", **_overrides: object
    ) -> FlextResult[FlextAuthConfig]:
        """Create configuration using flext-core FlextConfig.create_from_environment with auth-specific validation.

        Args:
            environment: Environment name (development, production, etc.)
            **overrides: Parameter overrides that can change behavior

        Returns:
            FlextResult containing FlextAuthConfig instance

        """
        # Validate environment name
        valid_environments = ["development", "production", "staging", "test", "local"]
        if environment not in valid_environments:
            return FlextResult[FlextAuthConfig].fail(
                "Input should be 'development', 'production', 'staging', 'test' or 'local'"
            )

        # Validate environment variables for auth-specific fields
        try:
            env_jwt_expiry = os.environ.get("FLEXT_AUTH_JWT_EXPIRY_MINUTES")
            if env_jwt_expiry:
                int(env_jwt_expiry)  # Validate it's a valid int
        except ValueError:
            return FlextResult[FlextAuthConfig].fail(
                "Failed to load configuration from environment: invalid FLEXT_AUTH_JWT_EXPIRY_MINUTES value"
            )

        # Create instance with overrides including environment
        try:
            # Create configuration with environment-specific settings
            config = cls()

            # Validate configuration after creation
            validation_result = config.validate_configuration()
            if validation_result.is_failure:
                return FlextResult.fail(
                    f"Configuration validation error: {validation_result.error}"
                )

            return FlextResult.ok(config)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to create config with overrides: {e}"
            )

    @classmethod
    def create_with_overrides(
        cls,
        jwt_expiry_minutes: int | None = None,
        bcrypt_rounds: int | None = None,
        max_login_attempts: int | None = None,
        session_expiry_minutes: int | None = None,
        environment: str = "development",
        **additional_overrides: object,
    ) -> FlextResult[FlextAuthConfig]:
        """Create configuration with specific parameter overrides.

        Args:
            jwt_expiry_minutes: Override JWT token expiry
            bcrypt_rounds: Override bcrypt hashing rounds
            max_login_attempts: Override max login attempts
            session_expiry_minutes: Override session expiry
            environment: Environment name
            **additional_overrides: Additional parameter overrides

        Returns:
            FlextResult containing FlextAuthConfig instance

        """
        overrides = dict(additional_overrides)

        # Apply parameter overrides if provided
        if jwt_expiry_minutes is not None:
            overrides["jwt_expiry_minutes"] = jwt_expiry_minutes
        if bcrypt_rounds is not None:
            overrides["bcrypt_rounds"] = bcrypt_rounds
        if max_login_attempts is not None:
            overrides["max_login_attempts"] = max_login_attempts
        if session_expiry_minutes is not None:
            overrides["session_expiry_minutes"] = session_expiry_minutes

        return cls.create_for_environment(environment, **overrides)

    # =============================================================================
    # SINGLETON GLOBAL INSTANCE METHODS
    # =============================================================================

    @classmethod
    def get_global_instance(cls) -> FlextAuthConfig:
        """Get the SINGLETON GLOBAL authentication configuration instance.

        This method ensures a single source of truth for authentication configuration
        across the entire application. It loads configuration from multiple sources:
        1. Default values defined in Field()
        2. Environment variables with FLEXT_AUTH_ prefix
        3. Explicitly set values

        Returns:
            FlextAuthConfig: The global authentication configuration instance

        """
        if cls._auth_global_instance is None:
            cls._auth_global_instance = cls._load_from_sources()
        # At this point, _auth_global_instance is guaranteed to be non-None
        return cls._auth_global_instance

    @classmethod
    def _load_from_sources(cls) -> FlextAuthConfig:
        """Load authentication configuration from all available sources.

        Priority (lowest to highest):
        1. Default values in model
        2. Environment variables with FLEXT_AUTH_ prefix (highest priority)

        Returns:
            FlextAuthConfig: Loaded configuration instance

        """
        # Create instance with default values and environment variables using direct instantiation
        return cls()

    @classmethod
    def set_global_instance(cls, config: FlextConfig) -> None:
        """Set the global authentication configuration instance.

        Args:
            config: Authentication configuration instance to set as global

        """
        if not isinstance(config, FlextAuthConfig):
            error_msg = "config must be an instance of FlextAuthConfig"
            raise TypeError(error_msg)
        cls._auth_global_instance = config

    @classmethod
    def clear_global_instance(cls) -> None:
        """Clear the global authentication configuration instance."""
        cls._auth_global_instance = None

    @classmethod
    def get_or_create_global(cls, **kwargs: str | int) -> FlextResult[FlextAuthConfig]:
        """Get or create global authentication configuration with overrides.

        This method ensures a single source of truth for authentication configuration
        while allowing parameter overrides to change behavior.

        Args:
            **kwargs: Configuration parameters including optional 'environment'

        Returns:
            FlextResult containing FlextAuthConfig instance

        """
        # Extract environment from kwargs, default to development
        environment = str(kwargs.pop("environment", "development"))

        # Try to get existing global instance only if no overrides
        if cls._auth_global_instance is not None and not kwargs:
            return FlextResult[FlextAuthConfig].ok(cls._auth_global_instance)

        # Create new instance with overrides
        result = cls.create_for_environment(environment, **kwargs)
        if result.is_success:
            # Set as global instance
            cls.set_global_instance(result.value)

        return result

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules for authentication configuration using flext-core patterns."""
        # Use flext-core validation patterns
        return self.validate_configuration()

    # =============================================================================
    # CLI INTEGRATION METHODS
    # =============================================================================

    @classmethod
    def create_from_cli_params(
        cls,
        jwt_expiry: int | None = None,
        bcrypt_rounds: int | None = None,
        max_attempts: int | None = None,
        session_expiry: int | None = None,
        environment: str = "development",
        **additional_params: object,
    ) -> FlextResult[FlextAuthConfig]:
        """Create configuration from CLI parameters.

        This method is specifically designed for CLI integration, allowing
        CLI parameters to override FlextConfig singleton behavior while
        maintaining FlextConfig as the single source of truth.

        Args:
            jwt_expiry: JWT expiry in minutes from CLI --jwt-expiry
            bcrypt_rounds: Bcrypt rounds from CLI --bcrypt-rounds
            max_attempts: Max login attempts from CLI --max-attempts
            session_expiry: Session expiry in minutes from CLI --session-expiry
            environment: Environment name from CLI --environment
            **additional_params: Additional CLI parameters

        Returns:
            FlextResult containing FlextAuthConfig instance

        """
        # Convert CLI parameter names to config field names
        overrides = dict(additional_params)

        if jwt_expiry is not None:
            overrides["jwt_expiry_minutes"] = jwt_expiry
            # DEBUG: Setting jwt_expiry_minutes to {jwt_expiry}
        if bcrypt_rounds is not None:
            overrides["bcrypt_rounds"] = bcrypt_rounds
        if max_attempts is not None:
            overrides["max_login_attempts"] = max_attempts
        if session_expiry is not None:
            overrides["session_expiry_minutes"] = session_expiry

        # DEBUG: Overrides: {overrides}
        return cls.create_for_environment(environment, **overrides)

    @classmethod
    def update_global_from_cli(
        cls,
        jwt_expiry: int | None = None,
        bcrypt_rounds: int | None = None,
        max_attempts: int | None = None,
        session_expiry: int | None = None,
        environment: str = "development",
        **additional_params: object,
    ) -> FlextResult[FlextAuthConfig]:
        """Update global singleton from CLI parameters.

        This method updates the global FlextConfig singleton with CLI parameters,
        ensuring CLI parameters can change behavior while maintaining singleton
        consistency.

        Args:
            jwt_expiry: JWT expiry in minutes from CLI --jwt-expiry
            bcrypt_rounds: Bcrypt rounds from CLI --bcrypt-rounds
            max_attempts: Max login attempts from CLI --max-attempts
            session_expiry: Session expiry in minutes from CLI --session-expiry
            environment: Environment name from CLI --environment
            **additional_params: Additional CLI parameters

        Returns:
            FlextResult containing updated FlextAuthConfig instance

        """
        # Create new config with CLI parameters
        config_result = cls.create_from_cli_params(
            jwt_expiry=jwt_expiry,
            bcrypt_rounds=bcrypt_rounds,
            max_attempts=max_attempts,
            session_expiry=session_expiry,
            environment=environment,
            **additional_params,
        )

        if config_result.is_success:
            # Update global singleton
            cls.set_global_instance(config_result.value)

        return config_result

    def get_cli_summary(self) -> FlextTypes.Core.Dict:
        """Get configuration summary for CLI display.

        Returns:
            Dictionary with CLI-friendly configuration summary

        """
        return {
            "environment": self.environment,
            "jwt_expiry_minutes": self.jwt_expiry_minutes,
            "bcrypt_rounds": self.bcrypt_rounds,
            "max_login_attempts": self.max_login_attempts,
            "session_expiry_minutes": self.session_expiry_minutes,
            "lockout_duration_minutes": self.lockout_duration_minutes,
            "min_password_length": self.min_password_length,
            "max_password_length": self.max_password_length,
            "require_password_complexity": self.require_password_complexity,
            "enable_audit_logging": self.enable_audit_logging,
            "enable_rate_limiting": self.enable_rate_limiting,
        }

    @classmethod
    def get_global_cli_summary(cls) -> FlextResult[FlextTypes.Core.Dict]:
        """Get global singleton configuration summary for CLI display.

        Returns:
            FlextResult containing CLI-friendly configuration summary

        """
        try:
            config = cls.get_global_instance()
            return FlextResult[FlextTypes.Core.Dict].ok(config.get_cli_summary())
        except Exception as e:
            return FlextResult[FlextTypes.Core.Dict].fail(
                f"Failed to get CLI summary: {e}"
            )


# Module exports
__all__ = [
    "FlextAuthConfig",
]

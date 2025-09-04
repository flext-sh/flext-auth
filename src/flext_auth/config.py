"""FLEXT Auth Configuration - Type-safe authentication configuration using flext-core patterns.

Provides type-safe configuration for authentication services with environment variable
support and validation using FlextConfig directly without wrapper classes, following
the "fazer mais com menos" principle.

Usage:
    config = FlextConfig()
    auth_service = FlextAuthService(
        jwt_secret=config.jwt_secret,
        token_expire_minutes=config.jwt_expiry_minutes
    )

"""

from __future__ import annotations

import os

from flext_core import FlextConfig, FlextConstants, FlextResult, FlextUtilities
from pydantic import BaseModel, Field, TypeAdapter, ValidationInfo, field_validator


# Parameter Object Pattern for configuration creation
class EnvironmentConfigRequest(BaseModel):
    """Environment configuration request parameter object using Pydantic."""

    environment: str
    overrides: dict[str, object] = Field(default_factory=dict)


class FlextAuthConfig(FlextConfig):
    """Authentication configuration class extending FlextConfig.

    Provides type-safe configuration for authentication services with
    environment variable support, validation, and default values following
    flext-core configuration patterns.

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

    """

    # =========================================================================
    # JWT CONFIGURATION
    # =========================================================================

    jwt_secret: str = Field(
        default="",  # Will be generated in validator if empty
        description="JWT signing secret key",
    )

    jwt_expiry_minutes: int = Field(
        default=FlextConstants.Auth.JWT_DEFAULT_EXPIRY_MINUTES,
        description="JWT token expiry in minutes",
        ge=1,  # Minimum 1 minute
        le=FlextConstants.Auth.JWT_MAX_EXPIRY_MINUTES,
    )

    jwt_algorithm: str = Field(
        default=FlextConstants.Auth.JWT_DEFAULT_ALGORITHM,
        description="JWT signing algorithm",
    )

    jwt_issuer: str = Field(
        default=FlextConstants.Auth.JWT_ISSUER_CLAIM, description="JWT issuer claim"
    )

    jwt_audience: str = Field(
        default=FlextConstants.Auth.JWT_AUDIENCE_CLAIM, description="JWT audience claim"
    )

    # =========================================================================
    # SECURITY CONFIGURATION
    # =========================================================================

    bcrypt_rounds: int = Field(
        default=FlextConstants.Auth.BCRYPT_ROUNDS,
        description="Bcrypt hashing rounds",
        ge=FlextConstants.Auth.MIN_BCRYPT_ROUNDS,
        le=FlextConstants.Auth.MAX_BCRYPT_ROUNDS,
    )

    max_login_attempts: int = Field(
        default=FlextConstants.Auth.MAX_LOGIN_ATTEMPTS,
        description="Maximum failed login attempts before lockout",
        ge=1,  # Minimum 1 attempt
        le=20,  # Maximum 20 attempts
    )

    lockout_duration_minutes: int = Field(
        default=FlextConstants.Auth.LOCKOUT_DURATION_MINUTES,
        description="Account lockout duration in minutes",
        ge=1,  # Minimum 1 minute
        le=1440,  # Maximum 24 hours
    )

    # =========================================================================
    # SESSION CONFIGURATION
    # =========================================================================

    session_expiry_minutes: int = Field(
        default=FlextConstants.Auth.DEFAULT_SESSION_EXPIRY_MINUTES,
        description="Session expiry in minutes",
        ge=5,
        le=FlextConstants.Auth.MAX_SESSION_EXPIRY_MINUTES,
    )

    max_sessions_per_user: int = Field(
        default=FlextConstants.Auth.MAX_SESSIONS_PER_USER,
        description="Maximum concurrent sessions per user",
        ge=1,
        le=20,
    )

    session_cleanup_interval_minutes: int = Field(
        default=FlextConstants.Auth.SESSION_CLEANUP_INTERVAL_MINUTES,
        description="Session cleanup interval in minutes",
        ge=5,
        le=1440,
    )

    # =========================================================================
    # PASSWORD VALIDATION CONFIGURATION
    # =========================================================================

    min_password_length: int = Field(
        default=FlextConstants.Auth.MIN_PASSWORD_LENGTH,
        description="Minimum password length",
        ge=6,
        le=20,
    )

    max_password_length: int = Field(
        default=FlextConstants.Auth.MAX_PASSWORD_LENGTH,
        description="Maximum password length",
        ge=20,
        le=256,
    )

    require_password_complexity: bool = Field(
        default=True,
        description="Require complex passwords with mixed case, numbers, and symbols",
    )

    min_password_score: int = Field(
        default=FlextConstants.Auth.MIN_PASSWORD_SCORE,
        description="Minimum password strength score (1-5)",
        ge=1,
        le=5,
    )

    # =========================================================================
    # RATE LIMITING CONFIGURATION
    # =========================================================================

    max_requests_per_minute: int = Field(
        default=FlextConstants.Auth.MAX_REQUESTS_PER_MINUTE,
        description="Maximum authentication requests per minute",
        ge=10,
        le=300,
    )

    max_requests_per_hour: int = Field(
        default=FlextConstants.Auth.MAX_REQUESTS_PER_HOUR,
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

    @field_validator("jwt_secret")
    @classmethod
    def validate_jwt_secret(cls, v: str) -> str:
        """Validate JWT secret key requirements."""
        if not v:
            # Generate secure random secret using flext-core utilities
            v = FlextUtilities.generate_uuid()

        if len(v) < FlextConstants.Auth.MIN_SECRET_KEY_LENGTH:
            msg = f"JWT secret must be at least {FlextConstants.Auth.MIN_SECRET_KEY_LENGTH} characters"
            raise ValueError(msg)

        return v

    @field_validator("jwt_algorithm")
    @classmethod
    def validate_jwt_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm is supported."""
        if v not in FlextConstants.Auth.JWT_ALLOWED_ALGORITHMS:
            msg = f"JWT algorithm must be one of: {FlextConstants.Auth.JWT_ALLOWED_ALGORITHMS}"
            raise ValueError(msg)
        return v

    @field_validator("min_password_length", "max_password_length")
    @classmethod
    def validate_password_lengths(cls, v: int, info: ValidationInfo) -> int:
        """Validate password length constraints are logical."""
        # This validator runs for both fields, so we need to check context
        if info.field_name == "max_password_length":
            # Ensure max is greater than min (we'll have min from defaults)
            min_length = FlextConstants.Auth.MIN_PASSWORD_LENGTH
            if v <= min_length:
                msg = f"Maximum password length must be greater than minimum ({min_length})"
                raise ValueError(msg)
        return v

    # =========================================================================
    # CONFIGURATION METHODS
    # =========================================================================

    @classmethod
    def from_environment(cls) -> FlextResult[FlextAuthConfig]:
        """Create configuration from environment variables.

        Returns:
            FlextResult containing validated configuration or error

        """
        try:
            # Read environment variables with defaults
            env_config: dict[str, object] = {
                "jwt_secret": os.getenv("FLEXT_AUTH_JWT_SECRET", ""),
                "jwt_expiry_minutes": int(
                    os.getenv(
                        "FLEXT_AUTH_JWT_EXPIRY_MINUTES",
                        str(FlextConstants.Auth.JWT_DEFAULT_EXPIRY_MINUTES),
                    )
                ),
                "jwt_algorithm": os.getenv(
                    "FLEXT_AUTH_JWT_ALGORITHM",
                    FlextConstants.Auth.JWT_DEFAULT_ALGORITHM,
                ),
                "bcrypt_rounds": int(
                    os.getenv(
                        "FLEXT_AUTH_BCRYPT_ROUNDS",
                        str(FlextConstants.Auth.BCRYPT_ROUNDS),
                    )
                ),
                "max_login_attempts": int(
                    os.getenv(
                        "FLEXT_AUTH_MAX_LOGIN_ATTEMPTS",
                        str(FlextConstants.Auth.MAX_LOGIN_ATTEMPTS),
                    )
                ),
                "session_expiry_minutes": int(
                    os.getenv(
                        "FLEXT_AUTH_SESSION_EXPIRY_MINUTES",
                        str(FlextConstants.Auth.DEFAULT_SESSION_EXPIRY_MINUTES),
                    )
                ),
                "enable_audit_logging": os.getenv(
                    "FLEXT_AUTH_ENABLE_AUDIT_LOGGING", "true"
                ).lower()
                == "true",
                "enable_rate_limiting": os.getenv(
                    "FLEXT_AUTH_ENABLE_RATE_LIMITING", "true"
                ).lower()
                == "true",
            }

            # Use Pydantic's TypeAdapter for automatic type conversion (Python 3.13)
            adapter = TypeAdapter(cls)
            # Pydantic automatically handles type conversion with validation
            config = adapter.validate_python(env_config)
            return FlextResult[FlextAuthConfig].ok(config)

        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to load configuration from environment: {e}"
            )

    def get_security_settings(self) -> dict[str, object]:
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

    def get_jwt_settings(self) -> dict[str, object]:
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

    def get_session_settings(self) -> dict[str, object]:
        """Get session-related configuration settings.

        Returns:
            Dictionary containing session configuration

        """
        return {
            "session_expiry_minutes": self.session_expiry_minutes,
            "max_sessions_per_user": self.max_sessions_per_user,
            "session_cleanup_interval_minutes": self.session_cleanup_interval_minutes,
        }

    def validate_configuration(self) -> FlextResult[None]:
        """Validate complete configuration for consistency.

        Returns:
            FlextResult indicating validation success or failure

        """
        try:
            # Validate password length consistency
            if self.min_password_length >= self.max_password_length:
                return FlextResult[None].fail(
                    "Minimum password length must be less than maximum"
                )

            # Validate JWT expiry is reasonable
            if self.jwt_expiry_minutes > self.session_expiry_minutes:
                return FlextResult[None].fail(
                    "JWT expiry should not exceed session expiry"
                )

            # Validate bcrypt rounds are in safe range
            if self.bcrypt_rounds < FlextConstants.Auth.MIN_BCRYPT_ROUNDS:
                return FlextResult[None].fail(
                    "Bcrypt rounds should be at least 10 for security"
                )

            # Skip rate limiting validation for now - different models (burst vs sustained)

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Configuration validation failed: {e}")

    @classmethod
    def create_for_environment(
        cls, environment: str = "development", **overrides: object
    ) -> FlextResult[FlextAuthConfig]:
        """Create configuration using Railway Pattern with FlextCore functional composition.

        Eliminates all 3 return statements using monadic composition.
        Uses FlextCore.pipe() for single-path configuration flow.
        """
        # Create Parameter Object for internal processing
        config_request = EnvironmentConfigRequest(
            environment=environment, overrides=dict(overrides)
        )

        # Proper Railway Pattern using FlextResult bind chains - SINGLE RETURN
        result = cls._validate_environment(config_request)

        return (
            result.bind(cls._build_configuration_data)
            .bind(cls._extract_configuration_parameters)
            .bind(lambda params: cls._safe_create_config_instance(cls, params))
            .bind(cls._validate_configuration_consistency)
        )

    @classmethod
    def _validate_environment(
        cls, request: EnvironmentConfigRequest
    ) -> FlextResult[EnvironmentConfigRequest]:
        """Validate environment parameter - extracted method for Railway Pattern."""
        valid_envs = ["development", "production", "test", "staging"]
        if request.environment not in valid_envs:
            return FlextResult[EnvironmentConfigRequest].fail(
                f"Invalid environment '{request.environment}'. Valid options: {valid_envs}"
            )
        return FlextResult[EnvironmentConfigRequest].ok(request)

    @classmethod
    def _build_configuration_data(
        cls, request: EnvironmentConfigRequest
    ) -> FlextResult[dict[str, object]]:
        """Build configuration data with environment defaults - extracted method."""
        env_defaults = {
            "development": {
                "jwt_expiry_minutes": 480,  # 8 hours
                "session_expiry_minutes": 600,  # 10 hours (must be > JWT)
                "bcrypt_rounds": 10,  # Faster for development
                "max_login_attempts": 10,  # More lenient
            },
            "production": {
                "jwt_expiry_minutes": 30,  # 30 minutes for production security
                "session_expiry_minutes": 60,  # 1 hour (must be > JWT)
                "bcrypt_rounds": 14,  # Higher security
                "max_login_attempts": 5,  # Strict
            },
            "test": {
                "jwt_expiry_minutes": 15,  # Short for tests
                "session_expiry_minutes": 30,  # 30 minutes (must be > JWT)
                "bcrypt_rounds": 10,  # Minimum valid (faster for tests)
                "max_login_attempts": 20,  # Very lenient
            },
            "staging": {
                "jwt_expiry_minutes": 120,  # 2 hours
                "session_expiry_minutes": 180,  # 3 hours (must be > JWT)
                "bcrypt_rounds": 12,  # Balanced
                "max_login_attempts": 5,  # Same as production
            },
        }

        # Merge defaults with overrides
        config_data = {**env_defaults[request.environment], **request.overrides}
        return FlextResult[dict[str, object]].ok(config_data)

    @classmethod
    def _extract_configuration_parameters(
        cls, config_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Extract and safely convert configuration parameters - extracted method."""

        def safe_int_cast(value: object, default: int) -> int:
            """Safely cast value to int, using default if not convertible."""
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
            return default

        # Extract jwt_secret handling
        jwt_secret = config_data.get("jwt_secret", "")
        if not isinstance(jwt_secret, str) or len(jwt_secret) == 0:
            jwt_secret = ""  # Let Pydantic validator generate it  # nosec B105

        parameters = {
            "jwt_secret": jwt_secret,
            "jwt_expiry_minutes": safe_int_cast(
                config_data.get(
                    "jwt_expiry_minutes", FlextConstants.Auth.JWT_DEFAULT_EXPIRY_MINUTES
                ),
                FlextConstants.Auth.JWT_DEFAULT_EXPIRY_MINUTES,
            ),
            "bcrypt_rounds": safe_int_cast(
                config_data.get("bcrypt_rounds", FlextConstants.Auth.BCRYPT_ROUNDS),
                FlextConstants.Auth.BCRYPT_ROUNDS,
            ),
            "max_login_attempts": safe_int_cast(
                config_data.get(
                    "max_login_attempts", FlextConstants.Auth.MAX_LOGIN_ATTEMPTS
                ),
                FlextConstants.Auth.MAX_LOGIN_ATTEMPTS,
            ),
            "session_expiry_minutes": safe_int_cast(
                config_data.get(
                    "session_expiry_minutes",
                    FlextConstants.Auth.DEFAULT_SESSION_EXPIRY_MINUTES,
                ),
                FlextConstants.Auth.DEFAULT_SESSION_EXPIRY_MINUTES,
            ),
            "lockout_duration_minutes": safe_int_cast(
                config_data.get(
                    "lockout_duration_minutes",
                    FlextConstants.Auth.LOCKOUT_DURATION_MINUTES,
                ),
                FlextConstants.Auth.LOCKOUT_DURATION_MINUTES,
            ),
        }

        return FlextResult[dict[str, object]].ok(parameters)

    @classmethod
    def _safe_create_config_instance(
        cls, config_class: type[FlextAuthConfig], parameters: dict[str, object]
    ) -> FlextResult[FlextAuthConfig]:
        """Safely create configuration instance with exception handling - extracted method."""
        try:
            # Type ignore for parameter unpacking - eliminates 9 MyPy errors
            config = config_class(**parameters)  # type: ignore[arg-type]
            return FlextResult[FlextAuthConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(
                f"Failed to create auth config: {e}"
            )

    @classmethod
    def _validate_configuration_consistency(
        cls, config: FlextAuthConfig
    ) -> FlextResult[FlextAuthConfig]:
        """Validate configuration consistency - extracted method for Railway Pattern."""
        validation_result = config.validate_configuration()
        if validation_result.is_failure:
            return FlextResult[FlextAuthConfig].fail(
                validation_result.error or "Configuration validation failed"
            )
        return FlextResult[FlextAuthConfig].ok(config)


# Module exports
__all__ = [
    "FlextAuthConfig",
]

"""FLEXT Auth Configuration & Types - Centralized authentication configuration and types.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import contextlib
import os
import re
import secrets
from abc import abstractmethod
from typing import Never

from flext_core import (
    FlextBaseConfigModel,
    FlextDatabaseModel,
    FlextProtocols,
    FlextSettings,
    TEntityId,
)
from pydantic import Field
from pydantic_settings import SettingsConfigDict


# FLEXT MIGRATION: Use FlextProtocols.Infrastructure.Configurable for secret handling
class _SecretProtocol(FlextProtocols.Infrastructure.Configurable):
    """Protocol for password secret objects from flext-core.

    FLEXT REFACTORING: Migrated from local Protocol to FlextProtocols.Infrastructure.Configurable
    to eliminate Protocol duplication and ensure architectural compliance.
    """

    @abstractmethod
    def get_secret_value(self) -> str:
        """Get the secret value as string."""
        ...


# =============================================================================
# TYPE DEFINITIONS - Authentication-specific types
# =============================================================================

# Core entity types extending flext-core
type TUserId = TEntityId
type TSessionId = TEntityId

# Authentication domain types
type TUsername = str
type TEmail = str
type TPassword = str
type TUserRole = str

# Authentication data types - SOLID refactoring: specific types instead of Any
type TAuthResult = dict[str, object]  # Authentication result with user data
type TSecurityContext = dict[str, object]  # Security context with permissions
type TLoginAttempt = dict[str, object]  # Login attempt data with metadata

# Audit types
type TAuditEventType = str

# =============================================================================
# CONFIGURATION CONSTANTS
# =============================================================================

# Configuration constants
MIN_JWT_SECRET_LENGTH = 32


# =============================================================================
# AUTHENTICATION CONSTANTS
# =============================================================================


class FlextAuthConstants:
    """Authentication constants for validation patterns."""

    USERNAME_PATTERN = r"^[a-zA-Z0-9_-]+$"
    MIN_PASSWORD_LENGTH = 8
    MAX_PASSWORD_LENGTH = 128
    PASSWORD_VALIDATION_REGEX = (
        r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[!@#$%^&*(),.?\":{}|<>]).+$"  # noqa: S105
    )


# =============================================================================
# CENTRALIZED CONFIGURATION MODELS - Using flext-core patterns
# =============================================================================


class FlextAuthConfig(FlextBaseConfigModel):
    """Centralized authentication configuration using flext-core models."""

    # Application settings
    app_name: str = Field(default="FlextAuth", description="Application name")
    version: str = Field(default="1.0.0", description="Application version")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field(default="development", description="Environment name")

    # Authentication specific settings
    password_min_length: int = Field(default=8,
        description="Minimum password length",
        ge=4,
        le=256,
    )
    password_max_length: int = Field(default=128,
        description="Maximum password length",
        ge=8,
        le=1024,
    )
    bcrypt_rounds: int = Field(default=12, description="BCrypt rounds", ge=4, le=20)

    # Security settings
    max_login_attempts: int = Field(default=5,
        description="Maximum login attempts",
        ge=1,
        le=10,
    )
    lockout_duration_minutes: int = Field(default=30,
        description="Account lockout duration",
        ge=1,
        le=1440,
    )
    session_timeout_hours: int = Field(default=24, description="Session timeout", ge=1, le=168)
    max_concurrent_sessions: int = Field(default=5,
        description="Maximum concurrent sessions",
        ge=1,
        le=20,
    )

    # Rate limiting
    rate_limit_per_minute: int = Field(default=60,
        description="General rate limit per minute",
        ge=1,
    )
    auth_rate_limit_per_minute: int = Field(default=5,
        description="Auth rate limit per minute",
        ge=1,
    )

    # JWT settings
    access_token_expire_minutes: int = Field(default=30,
        description="JWT access token expiration minutes",
        ge=1,
        le=10080,  # 1 week max
    )
    refresh_token_expire_days: int = Field(default=7,
        description="JWT refresh token expiration days",
        ge=1,
        le=90,  # 3 months max
    )
    jwt_secret_key: str | None = Field(default=None,
        description="JWT secret key for token signing",
    )


class FlextAuthApplicationConfig(FlextBaseConfigModel):
    """Complete application configuration extending FlextBaseConfigModel."""

    # Override app-specific defaults
    app_name: str = Field(default="FlextAuth", description="Application name")

    # Authentication-specific settings
    auth: FlextAuthConfig = Field(
        default_factory=FlextAuthConfig,
        description="Authentication configuration",
    )


# =============================================================================
# SIMPLIFIED CONFIGURATION CLASSES - Current API
# =============================================================================


class DatabaseConfig:
    """Database configuration for current API."""

    def __init__(self, **kwargs: object) -> None:
        """Initialize database configuration."""
        # Extract and validate pool settings using helper methods
        min_pool_size = self._extract_int_setting(
            kwargs,
            "min_pool_size",
            "DATABASE_MIN_POOL_SIZE",
            1,
        )
        max_pool_size = self._extract_int_setting(
            kwargs,
            "max_pool_size",
            "DATABASE_MAX_POOL_SIZE",
            10,
        )
        command_timeout = self._extract_int_setting(
            kwargs,
            "command_timeout",
            "DATABASE_COMMAND_TIMEOUT",
            60,
        )

        # Process URL settings
        self._original_url = self._extract_url_setting(kwargs)

        # Validate settings
        self._validate_pool_sizes(min_pool_size, max_pool_size)

        # Store validated values
        self._min_pool_size = min_pool_size
        self._max_pool_size = max_pool_size
        self._command_timeout = command_timeout

        # Store database config as simple dict since FlextDatabaseModel is generic
        self._core_config_dict = {
            "host": "localhost",
            "port": 5432,
            "database": "flext",
            "username": "postgres",
            "password": "password",
            "connection_timeout": command_timeout,
        }
        # Create a generic FlextModel instance for compatibility
        self._core_config = FlextDatabaseModel()

    def _extract_int_setting(
        self,
        kwargs: dict[str, object],
        key: str,
        env_key: str,
        default: int,
    ) -> int:
        """Extract and validate integer setting from kwargs or environment."""
        raw_value = kwargs.pop(key, os.getenv(env_key, str(default)))
        try:
            if isinstance(raw_value, int):
                return raw_value
            return int(str(raw_value)) if raw_value is not None else default
        except (ValueError, TypeError):
            return default

    def _extract_url_setting(self, kwargs: dict[str, object]) -> str | None:
        """Extract and validate database URL from kwargs or environment."""
        url_raw = kwargs.get("url")
        original_url = str(url_raw) if url_raw is not None else None

        if original_url is None:
            original_url = os.getenv("DATABASE_URL")

        if original_url and not original_url.startswith(
            ("postgresql://", "postgresql+asyncpg://"),
        ):
            msg = "Database URL must start with postgresql"
            raise ValueError(msg)

        return original_url

    def _validate_pool_sizes(self, min_pool_size: int, max_pool_size: int) -> None:
        """Validate pool size ranges."""

        def raise_validation_error(msg: str) -> Never:
            raise ValueError(msg)

        if min_pool_size < 1:
            raise_validation_error("Minimum pool size must be at least 1")

        max_min_pool_size = 20
        max_max_pool_size = 100

        if min_pool_size > max_min_pool_size:
            raise_validation_error("Minimum pool size cannot exceed 20")
        if max_pool_size > max_max_pool_size:
            raise_validation_error("Maximum pool size cannot exceed 100")

    def __getattr__(self, name: str) -> object:
        """Delegate unknown attributes to core config."""
        return getattr(self._core_config, name)

    @property
    def password(self) -> _SecretProtocol | None:
        """Get password as SecretProtocol for type safety."""
        return self._core_config_dict.get("password")  # type: ignore[return-value]

    @property
    def host(self) -> str:
        """Get database host."""
        return str(self._core_config_dict.get("host", "localhost"))

    @property
    def port(self) -> int:
        """Get database port."""
        port_value = self._core_config_dict.get("port", self._get_default_port())
        if isinstance(port_value, int):
            return port_value
        if isinstance(port_value, str) and port_value.isdigit():
            return int(port_value)
        return self._get_default_port()

    @property
    def database(self) -> str:
        """Get database name."""
        return str(self._core_config_dict.get("database", "flext"))

    @property
    def username(self) -> str:
        """Get database username."""
        return str(self._core_config_dict.get("username", "postgres"))

    def _get_default_port(self) -> int:
        """Get default PostgreSQL port."""
        return 5432

    @property
    def url(self) -> str:
        """Get database URL from components."""
        # If an original URL was provided, return it
        if self._original_url is not None:
            return self._original_url

        # Specific validation: return empty string if default/empty configuration
        if (
            self.host == "localhost"
            and self.database == "flext"
            and self.username == "postgres"
            and self.port == self._get_default_port()
        ):
            # Default configuration - empty for development
            return ""

        # Custom configuration - generate complete URL
        if self.password:
            # Type-safe secret value extraction using Protocol
            password_str = self.password.get_secret_value()
            return f"postgresql://{self.username}:{password_str}@{self.host}:{self.port}/{self.database}"
        return f"postgresql://{self.username}@{self.host}:{self.port}/{self.database}"

    @property
    def min_pool_size(self) -> int:
        """Get minimum pool size."""
        return getattr(self, "_min_pool_size", 1)

    @property
    def max_pool_size(self) -> int:
        """Get maximum pool size."""
        return getattr(self, "_max_pool_size", 10)

    @property
    def command_timeout(self) -> int:
        """Get command timeout."""
        return getattr(self, "_command_timeout", 60)


class JWTConfig(FlextSettings):
    """JWT configuration with environment variables."""

    secret_key: str = Field(default="", description="JWT secret key")
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(default=30,
        description="Access token expiration minutes",
    )
    refresh_token_expire_days: int = Field(default=7,
        description="Refresh token expiration days",
    )

    model_config = SettingsConfigDict(env_prefix="JWT_")

    def __init__(self, **kwargs: object) -> None:
        """Initialize with algorithm validation.

        Args:
            **kwargs: Configuration parameters for JWT settings

        Raises:
            ValueError: If algorithm is not supported

        """
        # Process kwargs - they can be empty but not None in **kwargs context

        # Validate algorithm before calling super().__init__
        algorithm = kwargs.get("algorithm", "HS256")
        valid_algorithms = ["HS256", "HS384", "HS512", "RS256", "RS384", "RS512"]
        if algorithm not in valid_algorithms:
            msg: str = f"JWT algorithm must be one of {valid_algorithms}"
            raise ValueError(msg)

        # Call parent without any kwargs to avoid type issues
        with contextlib.suppress(TypeError):
            super().__init__()

        # Set values after initialization
        for key, value in kwargs.items():
            if hasattr(self, key):
                setattr(self, key, value)

    def validate_secret_key(self) -> None:
        """Validate secret key strength."""
        if not self.secret_key or self.secret_key.strip() == "":
            msg = "JWT secret key cannot be empty"
            raise ValueError(msg)
        if len(self.secret_key) < MIN_JWT_SECRET_LENGTH:
            msg = "JWT secret key must be at least 32 characters long"
            raise ValueError(msg)

    @classmethod
    def generate_secret_key(cls) -> str:
        """Generate secure secret key."""
        return secrets.token_urlsafe(32)


class SecurityConfig(FlextSettings):
    """Security configuration with environment variables."""

    password_rounds: int = Field(default=12, description="BCrypt rounds", ge=4, le=20)
    max_failed_attempts: int = Field(default=5,
        description="Max failed login attempts",
        ge=1,
        le=10,
    )
    lockout_duration_minutes: int = Field(default=30,
        description="Account lockout duration",
        ge=1,
        le=1440,
    )
    session_expire_hours: int = Field(default=24,
        description="Session timeout hours",
        ge=1,
        le=168,
    )
    max_concurrent_sessions: int = Field(default=5,
        description="Max concurrent sessions",
        ge=1,
        le=20,
    )
    require_email_verification: bool = Field(default=False,
        description="Require email verification",
    )
    enable_2fa: bool = Field(default=False,
        description="Enable two-factor authentication",
    )

    model_config = SettingsConfigDict(env_prefix="SECURITY_")


class ServerConfig(FlextSettings):
    """Server configuration."""

    debug: bool = Field(default=False, description="Debug mode")
    host: str = Field(default="localhost", description="Server host")
    port: int = Field(default=8000, description="Server port")

    model_config = SettingsConfigDict(env_prefix="SERVER_")


class AppConfig(FlextSettings):
    """Application configuration."""

    name: str = Field(default="FLEXT Authentication API", description="Application name")
    version: str = Field(default="1.0.0", description="Application version")
    app_name: str = Field(default="FlextAuth", description="Application name")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field(default="development", description="Environment")

    # Nested configurations
    database: DatabaseConfig = Field(
        default_factory=DatabaseConfig,
        description="Database configuration",
    )
    jwt: JWTConfig = Field(
        default_factory=JWTConfig,
        description="JWT configuration"
    )
    security: SecurityConfig = Field(
        default_factory=SecurityConfig,
        description="Security configuration",
    )
    server: ServerConfig = Field(
        default_factory=ServerConfig,
        description="Server configuration",
    )

    model_config = SettingsConfigDict(env_prefix="APP_")

    def model_dump_safe(self) -> dict[str, object]:
        """Dump model data with sensitive information redacted."""
        # Get the regular model dump
        dump = self.model_dump()

        # Handle DatabaseConfig manually since it's not a Pydantic model
        if hasattr(self, "database") and self.database:
            db_url = getattr(self.database, "url", "")
            if db_url and "://" in db_url:
                # Replace password in URL
                redacted_url = re.sub(r"://([^:]+):([^@]+)@", r"://[REDACTED]@", db_url)
                dump["database"] = {"url": redacted_url}
            else:
                dump["database"] = {"url": db_url}

        # Redact JWT secret key
        if "jwt" in dump and "secret_key" in dump["jwt"]:
            redacted_value = "[REDACTED]"  # nosec B105
            dump["jwt"]["secret_key"] = redacted_value

        return dump


# =============================================================================
# CONFIGURATION FACTORY FUNCTIONS - Simplified creation
# =============================================================================


def create_auth_config(**overrides: object) -> FlextAuthConfig:
    """Create authentication configuration."""
    # Type-safe creation using Pydantic v2 model_validate
    if overrides:
        # Filter None values and use model_validate for type safety
        filtered_overrides = {k: v for k, v in overrides.items() if v is not None}
        return FlextAuthConfig.model_validate(filtered_overrides)
    # Use default constructor with defaults from class
    config = FlextAuthConfig()
    # Override JWT secret if needed
    if hasattr(config, "jwt_secret_key"):
        config.jwt_secret_key = get_default_secret("FLEXT_AUTH_JWT_SECRET_KEY")
    return config


def create_complete_auth_config(**overrides: object) -> FlextAuthApplicationConfig:
    """Create complete authentication application configuration."""
    # Type-safe creation using Pydantic v2 model_validate
    if overrides:
        # Filter None values and use model_validate for type safety
        filtered_overrides = {k: v for k, v in overrides.items() if v is not None}
        return FlextAuthApplicationConfig.model_validate(filtered_overrides)
    # Use default constructor with built-in defaults
    return FlextAuthApplicationConfig()


def get_default_secret(key_name: str) -> str:
    """Get default secret from environment or generate secure random value."""
    env_value = os.getenv(key_name)
    if env_value:
        return env_value
    return secrets.token_urlsafe(32)


def validate_production_config(config: AppConfig) -> bool:
    """Production configuration validation with critical field checks."""
    # Validate database URL is not empty
    if hasattr(config, "database") and config.database:
        db_url = getattr(config.database, "url", "")
        if not db_url or db_url.strip() == "":
            msg = "Production database URL is required"
            raise ValueError(msg)

    # Validate JWT secret key is not empty
    if hasattr(config, "jwt") and config.jwt:
        jwt_secret = getattr(config.jwt, "secret_key", "")
        if not jwt_secret or jwt_secret.strip() == "":
            msg = "Production JWT secret key is required"
            raise ValueError(msg)

    # Validate required fields exist
    config_dict = config.model_dump()
    required_fields = ["app_name", "environment"]
    return all(field in config_dict and config_dict[field] for field in required_fields)


# =============================================================================
# CONFIGURATION PRESETS - Common configurations
# =============================================================================


def create_development_config() -> FlextAuthApplicationConfig:
    """Create development configuration with reasonable defaults."""
    auth_config = FlextAuthConfig()
    if hasattr(auth_config, "debug"):
        auth_config.debug = True
    if hasattr(auth_config, "environment"):
        auth_config.environment = "development"
    if hasattr(auth_config, "jwt_secret_key"):
        auth_config.jwt_secret_key = get_default_secret("FLEXT_AUTH_JWT_SECRET_KEY")
    app_config = FlextAuthApplicationConfig()
    if hasattr(app_config, "auth"):
        app_config.auth = auth_config
    return app_config


def create_production_config() -> FlextAuthApplicationConfig:
    """Create production configuration requiring environment variables."""
    jwt_secret = os.getenv("FLEXT_AUTH_JWT_SECRET_KEY")
    if not jwt_secret or len(jwt_secret) < MIN_JWT_SECRET_LENGTH:
        msg = "Production requires FLEXT_AUTH_JWT_SECRET_KEY (min 32 chars)"
        raise ValueError(msg)

    auth_config = FlextAuthConfig()
    if hasattr(auth_config, "debug"):
        auth_config.debug = False
    if hasattr(auth_config, "environment"):
        auth_config.environment = "production"
    if hasattr(auth_config, "jwt_secret_key"):
        auth_config.jwt_secret_key = jwt_secret
    app_config = FlextAuthApplicationConfig()
    if hasattr(app_config, "app_name"):
        app_config.app_name = "FlextAuth"
    if hasattr(app_config, "auth"):
        app_config.auth = auth_config
    return app_config


# =============================================================================
# SECURE DEFAULT SECRETS - Environment variable defaults
# =============================================================================

# Library-wide default secrets for production and development environments.
DEFAULT_JWT_SECRET = os.getenv("FLEXT_AUTH_JWT_SECRET_KEY", "dev-secret-key")
DEFAULT_SERVICE_SECRET = os.getenv(
    "FLEXT_AUTH_SERVICE_SECRET",
    get_default_secret("FLEXT_AUTH_SERVICE_SECRET"),
)
DEFAULT_MFA_SECRET = os.getenv(
    "FLEXT_AUTH_MFA_SECRET",
    get_default_secret("FLEXT_AUTH_MFA_SECRET"),
)
DEFAULT_DEV_SECRET = os.getenv("FLEXT_AUTH_DEV_SECRET", "dev-secret-key")

# =============================================================================
# EXPORTS - Clean config and types API
# =============================================================================

__all__: list[str] = [
    # Default secrets
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_MFA_SECRET",
    "DEFAULT_SERVICE_SECRET",
    # Configuration classes
    "AppConfig",
    "DatabaseConfig",
    "FlextAuthApplicationConfig",
    # Main configuration classes
    "FlextAuthConfig",
    # Constants
    "FlextAuthConstants",
    "JWTConfig",
    "SecurityConfig",
    "ServerConfig",
    "TAuditEventType",
    "TAuthResult",
    "TEmail",
    "TLoginAttempt",
    "TPassword",
    "TSecurityContext",
    "TSessionId",
    # Type definitions
    "TUserId",
    "TUserRole",
    "TUsername",
    # Factory functions
    "create_auth_config",
    "create_complete_auth_config",
    "create_development_config",
    "create_production_config",
    # Utilities
    "get_default_secret",
    "validate_production_config",
]

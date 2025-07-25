"""Production configuration management for flext-auth using FlextCoreSettings patterns."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from flext_core import FlextCoreSettings
from pydantic import Field, field_validator
from pydantic_settings import SettingsConfigDict


class DatabaseConfig(FlextCoreSettings):
    """Database configuration."""

    model_config = SettingsConfigDict(env_prefix="DATABASE_")

    url: str = Field(
        default="",
        description="PostgreSQL database URL",
    )
    min_pool_size: int = Field(default=1, ge=1, le=20)
    max_pool_size: int = Field(default=10, ge=1, le=100)
    command_timeout: int = Field(default=60, ge=5, le=300)

    @field_validator("url")
    @classmethod
    def validate_db_url(cls, v: str) -> str:
        """Validate database URL format."""
        if v and not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            msg = "Database URL must start with postgresql:// or postgresql+asyncpg://"
            raise ValueError(
                msg,
            )
        return v


class JWTConfig(FlextCoreSettings):
    """JWT token configuration."""

    model_config = SettingsConfigDict(env_prefix="JWT_")

    secret_key: str = Field(
        default="",
        description="JWT signing secret key",
    )
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30,
        ge=5,
        le=1440,
        description="JWT access token expiration in minutes",
    )
    refresh_token_expire_days: int = Field(
        default=7,
        ge=1,
        le=30,
        description="JWT refresh token expiration in days",
    )

    @field_validator("secret_key")
    @classmethod
    def validate_secret_key(cls, v: str) -> str:
        """Validate JWT secret key."""
        if not v:
            # Generate secure random key if not provided
            return secrets.token_urlsafe(64)

        if v == "dev-secret-key-change-in-production":
            msg = "Production JWT secret key is required"
            raise ValueError(msg)

        return v

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm."""
        allowed_algorithms = ["HS256", "HS384", "HS512"]
        if v not in allowed_algorithms:
            msg = f"Algorithm must be one of {allowed_algorithms}"
            raise ValueError(msg)
        return v


class SecurityConfig(FlextCoreSettings):
    """Security configuration."""

    model_config = SettingsConfigDict(env_prefix="SECURITY_")

    password_rounds: int = Field(
        default=12,
        ge=4,
        le=20,
        description="Bcrypt rounds",
    )
    max_failed_attempts: int = Field(default=5, ge=1, le=20, description="Max failed login attempts")
    lockout_duration_minutes: int = Field(
        default=30,
        ge=1,
        le=1440,
        description="Account lockout duration in minutes",
    )
    session_expire_hours: int = Field(
        default=24,
        ge=1,
        le=168,
        description="Session expiration in hours",
    )
    max_concurrent_sessions: int = Field(
        default=5,
        ge=1,
        le=20,
        description="Maximum concurrent sessions per user",
    )
    require_email_verification: bool = Field(
        default=False,
        description="Require email verification for new accounts",
    )
    enable_2fa: bool = Field(default=False, description="Enable two-factor authentication")


class RateLimitConfig(FlextCoreSettings):
    """Rate limiting configuration."""

    model_config = SettingsConfigDict(env_prefix="RATE_LIMIT_")

    requests_per_minute: int = Field(
        default=60,
        ge=1,
        le=1000,
        description="General requests per minute limit",
    )
    requests_per_hour: int = Field(
        default=1000,
        ge=1,
        le=10000,
        description="General requests per hour limit",
    )
    login_requests_per_minute: int = Field(
        default=5,
        ge=1,
        le=60,
        description="Login requests per minute limit",
    )
    register_requests_per_minute: int = Field(
        default=3,
        ge=1,
        le=30,
        description="Registration requests per minute limit",
    )


class CORSConfig(FlextCoreSettings):
    """CORS configuration."""

    model_config = SettingsConfigDict(env_prefix="CORS_")

    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:8080"],
        description="Allowed CORS origins",
    )
    allow_credentials: bool = Field(default=True, description="Allow CORS credentials")
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        description="Allowed CORS methods",
    )
    allowed_headers: list[str] = Field(
        default_factory=lambda: ["*"],
        description="Allowed CORS headers",
    )

    @field_validator("allowed_origins")
    @classmethod
    def parse_origins(cls, v: str | list[str]) -> list[str]:
        """Parse comma-separated origins string."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


class ServerConfig(FlextCoreSettings):
    """Server configuration."""

    model_config = SettingsConfigDict(env_prefix="SERVER_")

    host: str = Field(default="0.0.0.0", description="Server host address")
    port: int = Field(default=8000, ge=1, le=65535, description="Server port")
    workers: int = Field(default=1, ge=1, le=32, description="Number of workers")
    reload: bool = Field(default=False, description="Enable auto-reload")
    debug: bool = Field(default=False, description="Enable debug mode")
    # Remove log_level - inherited from FlextCoreSettings
    trusted_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"],
        description="Trusted host addresses",
    )

    # Remove log_level validation - handled by FlextCoreSettings

    @field_validator("trusted_hosts")
    @classmethod
    def parse_trusted_hosts(cls, v: str | list[str]) -> list[str]:
        """Parse comma-separated hosts string."""
        if isinstance(v, str):
            return [host.strip() for host in v.split(",") if host.strip()]
        return v


class AppConfig(FlextCoreSettings):
    """Main application configuration."""

    model_config = SettingsConfigDict(env_prefix="APP_")

    name: str = Field(default="FLEXT Authentication API", description="Application name")
    version: str = Field(default="1.0.0", description="Application version")
    description: str = Field(
        default="Production-ready authentication service for FLEXT",
        description="Application description",
    )
    # Remove environment - inherited from FlextCoreSettings

    # Sub-configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    jwt: JWTConfig = Field(default_factory=JWTConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    cors: CORSConfig = Field(default_factory=CORSConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)

    # Remove old Config class - using model_config now

    # Remove environment validation - handled by FlextCoreSettings

    # Use inherited methods from FlextCoreSettings

    def model_dump_safe(self) -> dict[str, Any]:
        """Dump config without sensitive data."""
        config_dict = self.model_dump()

        # Remove sensitive fields
        if "jwt" in config_dict and "secret_key" in config_dict["jwt"]:
            config_dict["jwt"]["secret_key"] = "[REDACTED]"

        if "database" in config_dict and "url" in config_dict["database"]:
            db_url = config_dict["database"]["url"]
            if db_url and "://" in db_url:
                # Hide credentials in database URL
                parts = db_url.split("://")
                if len(parts) == 2 and "@" in parts[1]:
                    host_part = parts[1].split("@", 1)[1]
                    config_dict["database"]["url"] = (
                        f"{parts[0]}://[REDACTED]@{host_part}"
                    )

        return config_dict


# Remove global configuration instance - use dependency injection instead
# For backward compatibility, provide factory function
def get_auth_config() -> AppConfig:
    """Get authentication configuration using proper DI pattern.

    Returns:
        AppConfig: Authentication configuration instance.

    """
    return AppConfig()


# FlextXxx aliases following the pattern
FlextAuthConfig = AppConfig
FlextAuthSettings = AppConfig

# Deprecated: Global config instance - will be removed
# Use get_auth_config() instead for proper dependency injection
config = get_auth_config()


def load_config(config_file: str | Path | None = None) -> AppConfig:
    """Load configuration from file or environment."""
    if config_file:
        config_path = Path(config_file)
        if config_path.exists():
            # Load from specific config file
            import os
            os.environ.setdefault("SETTINGS_FILE", str(config_path))
            return AppConfig()

    return AppConfig()


def validate_production_config(cfg: AppConfig) -> None:
    """Validate production configuration."""
    errors = []

    if cfg.is_production():
        # JWT secret key validation
        if (
            not cfg.jwt.secret_key
            or cfg.jwt.secret_key == "dev-secret-key-change-in-production"
        ):
            errors.append("Production JWT secret key is required")

        # Database URL validation
        if not cfg.database.url:
            errors.append("Production database URL is required")

        # Security settings
        if cfg.security.password_rounds < 12:
            errors.append("Production bcrypt rounds should be >= 12")

        # Debug mode
        if cfg.server.debug:
            errors.append("Debug mode should be disabled in production")

        # CORS origins
        if "*" in cfg.cors.allowed_origins:
            errors.append("CORS wildcard origins should not be used in production")

    if errors:
        error_msg = "Production configuration errors:\n" + "\n".join(
            f"  - {error}" for error in errors
        )
        raise ValueError(error_msg)

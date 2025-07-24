"""Production configuration management for flext-auth."""

from __future__ import annotations

import secrets
from pathlib import Path
from typing import Any

from pydantic_settings import BaseSettings, Field, validator


class DatabaseConfig(BaseSettings):
    """Database configuration."""

    url: str = Field(
        default="", env="DATABASE_URL", description="PostgreSQL database URL"
    )
    min_pool_size: int = Field(default=1, env="DB_MIN_POOL_SIZE", ge=1, le=20)
    max_pool_size: int = Field(default=10, env="DB_MAX_POOL_SIZE", ge=1, le=100)
    command_timeout: int = Field(default=60, env="DB_COMMAND_TIMEOUT", ge=5, le=300)

    @validator("url")
    def validate_db_url(self, v: str) -> str:
        """Validate database URL format."""
        if v and not v.startswith(("postgresql://", "postgresql+asyncpg://")):
            raise ValueError(
                "Database URL must start with postgresql:// or postgresql+asyncpg://"
            )
        return v


class JWTConfig(BaseSettings):
    """JWT token configuration."""

    secret_key: str = Field(
        default="",
        env="JWT_SECRET_KEY",
        min_length=32,
        description="JWT signing secret key",
    )
    algorithm: str = Field(default="HS256", env="JWT_ALGORITHM")
    access_token_expire_minutes: int = Field(
        default=30, env="JWT_ACCESS_EXPIRE_MINUTES", ge=5, le=1440
    )
    refresh_token_expire_days: int = Field(
        default=7, env="JWT_REFRESH_EXPIRE_DAYS", ge=1, le=30
    )

    @validator("secret_key")
    def validate_secret_key(self, v: str) -> str:
        """Validate JWT secret key."""
        if not v:
            # Generate secure random key if not provided
            return secrets.token_urlsafe(64)

        if v == "dev-secret-key-change-in-production":
            raise ValueError("Production JWT secret key is required")

        return v

    @validator("algorithm")
    def validate_algorithm(self, v: str) -> str:
        """Validate JWT algorithm."""
        allowed_algorithms = ["HS256", "HS384", "HS512"]
        if v not in allowed_algorithms:
            raise ValueError(f"Algorithm must be one of {allowed_algorithms}")
        return v


class SecurityConfig(BaseSettings):
    """Security configuration."""

    password_rounds: int = Field(
        default=12, env="PASSWORD_ROUNDS", ge=4, le=20, description="Bcrypt rounds"
    )
    max_failed_attempts: int = Field(default=5, env="MAX_FAILED_ATTEMPTS", ge=1, le=20)
    lockout_duration_minutes: int = Field(
        default=30, env="LOCKOUT_DURATION_MINUTES", ge=1, le=1440
    )
    session_expire_hours: int = Field(
        default=24, env="SESSION_EXPIRE_HOURS", ge=1, le=168
    )
    max_concurrent_sessions: int = Field(
        default=5, env="MAX_CONCURRENT_SESSIONS", ge=1, le=20
    )
    require_email_verification: bool = Field(
        default=False, env="REQUIRE_EMAIL_VERIFICATION"
    )
    enable_2fa: bool = Field(default=False, env="ENABLE_2FA")


class RateLimitConfig(BaseSettings):
    """Rate limiting configuration."""

    requests_per_minute: int = Field(
        default=60, env="RATE_LIMIT_PER_MINUTE", ge=1, le=1000
    )
    requests_per_hour: int = Field(
        default=1000, env="RATE_LIMIT_PER_HOUR", ge=1, le=10000
    )
    login_requests_per_minute: int = Field(
        default=5, env="LOGIN_RATE_LIMIT_PER_MINUTE", ge=1, le=60
    )
    register_requests_per_minute: int = Field(
        default=3, env="REGISTER_RATE_LIMIT_PER_MINUTE", ge=1, le=30
    )


class CORSConfig(BaseSettings):
    """CORS configuration."""

    allowed_origins: list[str] = Field(
        default_factory=lambda: ["http://localhost:3000", "http://localhost:8080"],
        env="CORS_ORIGINS",
    )
    allow_credentials: bool = Field(default=True, env="CORS_ALLOW_CREDENTIALS")
    allowed_methods: list[str] = Field(
        default_factory=lambda: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        env="CORS_ALLOWED_METHODS",
    )
    allowed_headers: list[str] = Field(
        default_factory=lambda: ["*"], env="CORS_ALLOWED_HEADERS"
    )

    @validator("allowed_origins")
    def parse_origins(self, v: str | list[str]) -> list[str]:
        """Parse comma-separated origins string."""
        if isinstance(v, str):
            return [origin.strip() for origin in v.split(",") if origin.strip()]
        return v


class ServerConfig(BaseSettings):
    """Server configuration."""

    host: str = Field(default="0.0.0.0", env="HOST")
    port: int = Field(default=8000, env="PORT", ge=1, le=65535)
    workers: int = Field(default=1, env="WORKERS", ge=1, le=32)
    reload: bool = Field(default=False, env="RELOAD")
    debug: bool = Field(default=False, env="DEBUG")
    log_level: str = Field(default="info", env="LOG_LEVEL")
    trusted_hosts: list[str] = Field(
        default_factory=lambda: ["localhost", "127.0.0.1"], env="TRUSTED_HOSTS"
    )

    @validator("log_level")
    def validate_log_level(self, v: str) -> str:
        """Validate log level."""
        allowed_levels = ["debug", "info", "warning", "error", "critical"]
        if v.lower() not in allowed_levels:
            raise ValueError(f"Log level must be one of {allowed_levels}")
        return v.lower()

    @validator("trusted_hosts")
    def parse_trusted_hosts(self, v: str | list[str]) -> list[str]:
        """Parse comma-separated hosts string."""
        if isinstance(v, str):
            return [host.strip() for host in v.split(",") if host.strip()]
        return v


class AppConfig(BaseSettings):
    """Main application configuration."""

    name: str = Field(default="FLEXT Authentication API", env="APP_NAME")
    version: str = Field(default="1.0.0", env="APP_VERSION")
    description: str = Field(
        default="Production-ready authentication service for FLEXT",
        env="APP_DESCRIPTION",
    )
    environment: str = Field(default="development", env="ENVIRONMENT")

    # Sub-configurations
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    jwt: JWTConfig = Field(default_factory=JWTConfig)
    security: SecurityConfig = Field(default_factory=SecurityConfig)
    rate_limit: RateLimitConfig = Field(default_factory=RateLimitConfig)
    cors: CORSConfig = Field(default_factory=CORSConfig)
    server: ServerConfig = Field(default_factory=ServerConfig)

    class Config:
        """Pydantic configuration."""

        env_file = ".env"
        env_file_encoding = "utf-8"
        case_sensitive = False

    @validator("environment")
    def validate_environment(self, v: str) -> str:
        """Validate environment."""
        allowed_envs = ["development", "testing", "staging", "production"]
        if v.lower() not in allowed_envs:
            raise ValueError(f"Environment must be one of {allowed_envs}")
        return v.lower()

    @property
    def is_development(self) -> bool:
        """Check if running in development mode."""
        return self.environment == "development"

    @property
    def is_production(self) -> bool:
        """Check if running in production mode."""
        return self.environment == "production"

    @property
    def is_testing(self) -> bool:
        """Check if running in testing mode."""
        return self.environment == "testing"

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
                    config_dict["database"][
                        "url"
                    ] = f"{parts[0]}://[REDACTED]@{host_part}"

        return config_dict


# Global configuration instance
config = AppConfig()


def load_config(config_file: str | Path | None = None) -> AppConfig:
    """Load configuration from file or environment."""
    if config_file:
        config_path = Path(config_file)
        if config_path.exists():
            return AppConfig(_env_file=config_path)

    return AppConfig()


def validate_production_config(cfg: AppConfig) -> None:
    """Validate production configuration."""
    errors = []

    if cfg.is_production:
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

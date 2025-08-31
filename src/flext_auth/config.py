"""FLEXT Auth Configuration - Type-safe configuration management.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os

from pydantic import BaseModel, Field

from flext_auth.constants import FlextAuthConstants
from flext_auth.typings import FlextAuthTypes


class DatabaseConfig(BaseModel):
    """Database configuration settings."""

    url: FlextAuthTypes.URL = Field(
        default="sqlite:///auth.db", description="Database URL"
    )
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Maximum pool overflow")
    echo: bool = Field(default=False, description="Echo SQL queries")


class JWTConfig(BaseModel):
    """JWT configuration settings."""

    secret_key: FlextAuthTypes.String = Field(
        default=FlextAuthConstants.DEFAULT_JWT_SECRET, description="JWT secret key"
    )
    algorithm: FlextAuthTypes.String = Field(
        default="HS256", description="JWT algorithm"
    )
    access_token_expire_minutes: int = Field(
        default=FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES,
        description="Access token expiration in minutes",
    )
    refresh_token_expire_days: int = Field(
        default=FlextAuthConstants.DEFAULT_REFRESH_TOKEN_DAYS,
        description="Refresh token expiration in days",
    )


class SecurityConfig(BaseModel):
    """Security configuration settings."""

    bcrypt_rounds: int = Field(
        default=FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS,
        description="Bcrypt hash rounds",
    )
    max_login_attempts: int = Field(
        default=FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS,
        description="Maximum failed login attempts before lockout",
    )
    lockout_duration_minutes: int = Field(
        default=FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES,
        description="Account lockout duration in minutes",
    )
    session_timeout_hours: int = Field(
        default=FlextAuthConstants.DEFAULT_SESSION_TIMEOUT_HOURS,
        description="Session timeout in hours",
    )


class AppConfig(BaseModel):
    """Main application configuration."""

    # Environment
    environment: FlextAuthTypes.String = Field(
        default=os.getenv("FLEXT_ENV", "development"),
        description="Application environment",
    )
    debug: bool = Field(default=False, description="Debug mode")

    # Sub-configurations
    database: DatabaseConfig = Field(
        default_factory=DatabaseConfig, description="Database configuration"
    )
    jwt: JWTConfig = Field(default_factory=JWTConfig, description="JWT configuration")
    security: SecurityConfig = Field(
        default_factory=SecurityConfig, description="Security configuration"
    )

    # Service settings
    host: FlextAuthTypes.String = Field(default="localhost", description="Service host")
    port: int = Field(default=8000, description="Service port")

    @classmethod
    def from_env(cls) -> AppConfig:
        """Create configuration from environment variables."""
        return cls(
            environment=os.getenv("FLEXT_ENV", "development"),
            debug=os.getenv("FLEXT_DEBUG", "false").lower() == "true",
            database=DatabaseConfig(
                url=os.getenv("DATABASE_URL", "sqlite:///auth.db"),
                echo=os.getenv("DB_ECHO", "false").lower() == "true",
            ),
            jwt=JWTConfig(
                secret_key=os.getenv(
                    "JWT_SECRET_KEY", FlextAuthConstants.DEFAULT_JWT_SECRET
                ),
                access_token_expire_minutes=int(
                    os.getenv("JWT_ACCESS_EXPIRE_MINUTES", "30")
                ),
            ),
            security=SecurityConfig(
                bcrypt_rounds=int(os.getenv("BCRYPT_ROUNDS", "12")),
                max_login_attempts=int(os.getenv("MAX_LOGIN_ATTEMPTS", "5")),
                lockout_duration_minutes=int(
                    os.getenv("LOCKOUT_DURATION_MINUTES", "30")
                ),
            ),
            host=os.getenv("HOST", "localhost"),
            port=int(os.getenv("PORT", "8000")),
        )


def validate_production_config(config: AppConfig) -> list[str]:
    """Validate configuration for production use."""
    issues = []

    # Check JWT secret in production
    if config.environment == "production":
        if config.jwt.secret_key == FlextAuthConstants.DEFAULT_JWT_SECRET:
            issues.append("Using default JWT secret key in production is insecure")

        if (
            config.security.bcrypt_rounds
            < FlextAuthConstants.MIN_PRODUCTION_BCRYPT_ROUNDS
        ):
            issues.append(
                f"Bcrypt rounds too low for production (minimum: {FlextAuthConstants.MIN_PRODUCTION_BCRYPT_ROUNDS})"
            )

        if config.database.url.startswith("sqlite://"):
            issues.append("SQLite database not recommended for production")

    return issues


# Value objects for type safety
class FlextUserEmail(BaseModel):
    """Type-safe email value object."""

    value: FlextAuthTypes.String = Field(..., description="Email address")

    def __str__(self) -> str:
        """Return the email address as a string."""
        return self.value


class FlextUsername(BaseModel):
    """Type-safe username value object."""

    value: FlextAuthTypes.String = Field(..., description="Username")

    def __str__(self) -> str:
        """Return the username as a string."""
        return self.value


class FlextJWTClaims(BaseModel):
    """JWT claims structure."""

    sub: FlextAuthTypes.String = Field(..., description="Subject (user ID)")
    username: FlextAuthTypes.String = Field(..., description="Username")
    role: FlextAuthTypes.String = Field(..., description="User role")
    iat: int = Field(..., description="Issued at timestamp")
    exp: int = Field(..., description="Expiration timestamp")
    iss: FlextAuthTypes.String = Field(default="flext-auth", description="Issuer")


__all__ = [
    "AppConfig",
    "DatabaseConfig",
    "FlextJWTClaims",
    "FlextUserEmail",
    "FlextUsername",
    "JWTConfig",
    "SecurityConfig",
    "validate_production_config",
]

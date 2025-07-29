"""Authentication configuration using flext-core patterns.

Simplified configuration eliminating duplication and leveraging flext-core's
configuration patterns directly.
"""

from __future__ import annotations

import os
import secrets

# Use flext-core configuration patterns directly
from flext_core import FlextBaseSettings
from pydantic import Field

# =============================================================================
# COMPATIBILITY CONFIGURATION CLASSES - For backward compatibility
# =============================================================================


class AppConfig(FlextBaseSettings):
    """Application configuration for backward compatibility."""

    app_name: str = Field(default="FlextAuth", description="Application name")
    debug: bool = Field(default=False, description="Debug mode")
    environment: str = Field(default="development", description="Environment")


class DatabaseConfig(FlextBaseSettings):
    """Database configuration for backward compatibility."""

    database_url: str = Field(default="sqlite:///auth.db", description="Database URL")
    pool_size: int = Field(default=10, description="Connection pool size")
    max_overflow: int = Field(default=20, description="Max overflow connections")


class JWTConfig(FlextBaseSettings):
    """JWT configuration for backward compatibility."""

    secret_key: str = Field(default="dev-secret-key", description="JWT secret key")
    algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30,
        description="Access token expiration",
    )
    refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration",
    )


class SecurityConfig(FlextBaseSettings):
    """Security configuration for backward compatibility."""

    bcrypt_rounds: int = Field(default=12, description="BCrypt rounds")
    max_login_attempts: int = Field(default=5, description="Max failed login attempts")
    lockout_duration_minutes: int = Field(
        default=15,
        description="Account lockout duration",
    )


def validate_production_config(config: dict[str, object]) -> bool:
    """Validate production configuration."""
    required_fields = ["jwt_secret_key", "database_url"]
    return all(field in config for field in required_fields)


# =============================================================================
# AUTHENTICATION CONFIGURATION - Using flext-core efficiently
# =============================================================================


class FlextAuthConfig(FlextBaseSettings):
    """Authentication configuration using flext-core patterns."""

    # JWT settings
    jwt_secret_key: str = Field(default="dev-secret-key", description="JWT secret key")
    jwt_algorithm: str = Field(default="HS256", description="JWT algorithm")
    access_token_expire_minutes: int = Field(
        default=30,
        description="Access token expiration",
    )
    refresh_token_expire_days: int = Field(
        default=7,
        description="Refresh token expiration",
    )

    # Password settings
    password_min_length: int = Field(default=8, description="Minimum password length")
    password_max_length: int = Field(default=128, description="Maximum password length")
    bcrypt_rounds: int = Field(default=12, description="Bcrypt rounds")

    # Security settings
    max_login_attempts: int = Field(default=5, description="Maximum login attempts")
    lockout_duration_minutes: int = Field(
        default=30,
        description="Account lockout duration",
    )
    session_timeout_hours: int = Field(default=24, description="Session timeout")
    max_concurrent_sessions: int = Field(
        default=5,
        description="Maximum concurrent sessions",
    )

    def __init__(self, **data: object) -> None:
        """Initialize config with nested structure support."""
        # Handle nested config structure like {"security": {"password_rounds": 6}}
        if "security" in data:
            security_config = data.pop("security")
            if (
                isinstance(security_config, dict)
                and "password_rounds" in security_config
            ):
                data["bcrypt_rounds"] = security_config["password_rounds"]

        if "jwt" in data:
            jwt_config = data.pop("jwt")
            if isinstance(jwt_config, dict):
                for key, value in jwt_config.items():
                    if key == "secret_key":
                        data["jwt_secret_key"] = value
                    elif key in {
                        "algorithm",
                        "access_token_expire_minutes",
                        "refresh_token_expire_days",
                    }:
                        data[f"jwt_{key}"] = value

        # Convert data keys to proper types for pydantic
        processed_data: dict[str, object] = {}
        for key, value in data.items():
            processed_data[str(key)] = value

        super().__init__(**processed_data)  # type: ignore[arg-type]

        # Store nested objects for backward compatibility
        self._security = type(
            "SecurityConfig",
            (),
            {
                "password_rounds": self.bcrypt_rounds,
            },
        )()

        self._jwt = type(
            "JWTConfig",
            (),
            {
                "secret_key": self.jwt_secret_key,
                "algorithm": self.jwt_algorithm,
                "access_token_expire_minutes": self.access_token_expire_minutes,
                "refresh_token_expire_days": self.refresh_token_expire_days,
            },
        )()

    def __getattr__(self, name: str) -> object:
        """Provide backward compatibility for nested config access."""
        if name == "security":
            return self._security
        if name == "jwt":
            return self._jwt
        error_message = f"'{self.__class__.__name__}' object has no attribute '{name}'"
        raise AttributeError(error_message)

    class Config:
        """Pydantic configuration for FlextAuthConfig."""

        env_prefix = "FLEXT_AUTH_"
        extra = "ignore"  # Allow extra fields from flext-core environment


# =============================================================================
# SECURE DEFAULT SECRETS - Environment variable fallbacks
# =============================================================================


def get_default_secret(key_name: str) -> str:
    """Get default secret from environment or generate secure fallback.

    Args:
        key_name: Name of the environment variable to check

    Returns:
        Secure secret string from environment or generated fallback

    """
    # Try environment variable first
    env_value = os.getenv(key_name)
    if env_value:
        return env_value

    # Generate warning-inducing fallback
    secure_bytes = secrets.token_bytes(32)
    return secure_bytes.hex()


# Default secrets with environment variable support
DEFAULT_JWT_SECRET = os.getenv("FLEXT_AUTH_JWT_SECRET_KEY", "dev-secret-key")
DEFAULT_SERVICE_SECRET = os.getenv(
    "FLEXT_AUTH_SERVICE_SECRET",
    "flext-auth-service-secret-256bit-key-123456789012345678901234567890",
)
DEFAULT_MFA_SECRET = os.getenv(
    "FLEXT_AUTH_MFA_SECRET",
    "flext-auth-mfa-secret-256bit-key-123456789012345678901234567890123",
)
DEFAULT_DEV_SECRET = os.getenv("FLEXT_AUTH_DEV_SECRET", "dev-secret-key")


# =============================================================================
# EXPORTS - Clean config API
# =============================================================================

__all__ = [
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_MFA_SECRET",
    "DEFAULT_SERVICE_SECRET",
    "FlextAuthConfig",
    "get_default_secret",
]

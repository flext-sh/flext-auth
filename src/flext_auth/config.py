"""FLEXT Auth Configuration - Modern Python 3.13 + Clean Architecture + DI.

REFACTORED:
    Uses flext-core BaseSettings with value objects and constants.
Zero tolerance for duplication.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any, TYPE_CHECKING

from pydantic import Field
from pydantic import SecretStr
from pydantic import field_validator
from pydantic_settings import SettingsConfigDict

from flext_core.config import BaseSettings
from flext_core.config import get_container

from flext_core.domain.pydantic_base import DomainValueObject



if TYPE_CHECKING:
    from flext_core.domain.types import EnvironmentLiteral


class JWTConfig(DomainValueObject):
    """JWT configuration value object."""

    algorithm: str = Field("HS256", description="JWT signing algorithm (HS256, RS256)")
    secret_key: SecretStr = Field(
        default=SecretStr("change-this-secret-in-production"),
        description="Secret key for JWT signing",
    )
    access_token_expire_minutes: int = Field(
        30,
        ge=1,
        le=1440,
        description="Access token expiration in minutes",
    )
    refresh_token_expire_days: int = Field(
        7,
        ge=1,
        le=30,
        description="Refresh token expiration in days",
    )
    issuer: str = Field("flext-auth", description="JWT issuer")
    audience: str = Field("flext-auth", description="JWT audience")
    leeway_seconds: int = Field(
        5,
        ge=0,
        le=60,
        description="JWT validation leeway in seconds",
    )
    public_key: str | None = Field(None, description="RSA public key for RS256")
    private_key: SecretStr | None = Field(
        default=None, description="RSA private key for RS256"
    )

    @field_validator("algorithm")
    @classmethod
    def validate_algorithm(cls, v: str) -> str:
        """Validate JWT algorithm.

        Args:
            v: Algorithm name to validate.

        Returns:
            Validated algorithm name.

        Raises:
            ValueError: If algorithm is not supported.

        """
        allowed = {"HS256", "HS384", "HS512", "RS256", "RS384", "RS512"}
        if v not in allowed:
            msg = f"Algorithm must be one of {allowed}"
            raise ValueError(msg)
        return v


class PasswordConfig(DomainValueObject):
    """Password configuration value object."""

    min_length: int = Field(8, ge=4, le=128, description="Minimum password length")
    require_uppercase: bool = Field(True, description="Require uppercase letters")
    require_lowercase: bool = Field(True, description="Require lowercase letters")
    require_numbers: bool = Field(True, description="Require numbers")
    require_special: bool = Field(False, description="Require special characters")
    bcrypt_rounds: int = Field(
        12,
        ge=4,
        le=15,
        description="Bcrypt rounds for password hashing",
    )


class SessionConfig(DomainValueObject):
    """Session configuration value object."""

    timeout_hours: int = Field(24, ge=1, le=168, description="Session timeout in hours")
    max_sessions_per_user: int = Field(
        5,
        ge=1,
        le=50,
        description="Maximum concurrent sessions per user",
    )
    cleanup_interval_minutes: int = Field(
        60,
        ge=1,
        le=1440,
        description="Session cleanup interval in minutes",
    )
    extend_on_activity: bool = Field(True, description="Extend session on activity")


class SecurityConfig(DomainValueObject):
    """Security configuration value object."""

    max_failed_login_attempts: int = Field(
        5,
        ge=1,
        le=20,
        description="Maximum failed login attempts before lockout",
    )
    account_lockout_duration_minutes: int = Field(
        30,
        ge=1,
        le=1440,
        description="Account lockout duration in minutes",
    )
    require_email_verification: bool = Field(
        True,
        description="Require email verification for new accounts",
    )
    email_verification_token_expire_hours: int = Field(
        24,
        ge=1,
        le=168,
        description="Email verification token expiration in hours",
    )
    password_reset_token_expire_hours: int = Field(
        1,
        ge=1,
        le=24,
        description="Password reset token expiration in hours",
    )


class RedisConfig(DomainValueObject):
    """Redis configuration value object."""

    url: str = Field("redis://localhost:6379/0", description="Redis connection URL")
    pool_size: int = Field(
        20,
        ge=1,
        le=100,
        description="Redis connection pool size",
    )
    key_prefix: str = Field("flext:auth:", description="Redis key prefix")


class AuthSettings(BaseSettings):
    """FLEXT Auth configuration settings with environment variable support.

    All settings can be overridden via environment variables with the
    prefix FLEXT_AUTH_ (e.g., FLEXT_AUTH_JWT__SECRET_KEY).

    Uses flext-core BaseSettings foundation with DI support.
    """

    model_config = SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
        validate_assignment=True,
        str_strip_whitespace=True,
        use_enum_values=True,
    )

    # Project identification
    project_name: str = Field("flext-auth", description="Project name")
    project_version: str = Field("0.7.0", description="Project version")

    # Configuration value objects
    jwt: JWTConfig = Field(default=JWTConfig(), description="JWT configuration")  # type: ignore[call-arg]
    password: PasswordConfig = Field(
        default=PasswordConfig(),  # type: ignore[call-arg]
        description="Password configuration",
    )
    session: SessionConfig = Field(
        default=SessionConfig(),  # type: ignore[call-arg]
        description="Session configuration",
    )
    security: SecurityConfig = Field(
        default=SecurityConfig(),  # type: ignore[call-arg]
        description="Security configuration",
    )
    redis: RedisConfig = Field(
        default=RedisConfig(),  # type: ignore[call-arg]
        description="Redis configuration",
    )

    # Database settings
    database_url: str = Field(
        "postgresql://localhost/flext_auth",
        description="Database connection URL",
    )
    database_pool_size: int = Field(
        20,
        ge=1,
        le=100,
        description="Database connection pool size",
    )

    # Environment and debugging
    environment: EnvironmentLiteral = Field("development", description="Environment name")
    debug: bool = Field(False, description="Debug mode")

    @property
    def session_timeout_timedelta(self) -> timedelta:
        """Get session timeout as timedelta.

        Returns:
            Session timeout as timedelta object.

        """
        return timedelta(hours=self.session.timeout_hours)

    @property
    def session_cleanup_interval_timedelta(self) -> timedelta:
        """Get session cleanup interval as timedelta.

        Returns:
            Cleanup interval as timedelta object.

        """
        return timedelta(minutes=self.session.cleanup_interval_minutes)

    def get_jwt_config_dict(self) -> dict:
        """Get JWT configuration as dictionary.

        Returns:
            Dictionary with JWT configuration values.

        """
        return {
            "algorithm": self.jwt.algorithm,
            "secret_key": self.jwt.secret_key.get_secret_value(),
            "access_token_expire_minutes": self.jwt.access_token_expire_minutes,
            "refresh_token_expire_days": self.jwt.refresh_token_expire_days,
            "issuer": self.jwt.issuer,
            "audience": self.jwt.audience,
            "leeway_seconds": self.jwt.leeway_seconds,
            "public_key": self.jwt.public_key,
            "private_key": (
                self.jwt.private_key.get_secret_value()
                if self.jwt.private_key
                else None
            ),
        }

    def configure_dependencies(self, container: Any = None) -> None:
        """Configure dependencies in container.

        Args:
            container: Dependency injection container.

        """
        if container is None:
            container = get_container()

        # Register this settings instance
        container.register(AuthSettings, self)

        # Call parent configuration
        super().configure_dependencies(container)


# Convenience functions for getting settings
def get_auth_settings() -> AuthSettings:
    """Get authentication settings instance.

    Returns:
        Configured AuthSettings instance.

    """
    # Force model rebuild to resolve forward references
    try:
        AuthSettings.model_rebuild()
    except Exception:
        pass  # Already built or not needed

    return AuthSettings(
        project_name="flext-auth",
        project_version="0.7.0",
        environment="development",
        debug=False,
        database_url="postgresql://localhost/flext_auth",
        database_pool_size=20,
    )


def create_development_auth_config() -> AuthSettings:
    """Create development authentication configuration.

    Returns:
        AuthSettings configured for development.

    """
    return AuthSettings(
        project_name="flext-auth",
        project_version="0.7.0",
        environment="development",
        debug=True,
        database_url="postgresql://localhost/flext_auth_dev",
        database_pool_size=10,
        jwt=JWTConfig(  # type: ignore[call-arg]
            secret_key=SecretStr("development-secret-key-change-in-production"),
            access_token_expire_minutes=60,
        ),
        security=SecurityConfig(  # type: ignore[call-arg]
            require_email_verification=False,
            max_failed_login_attempts=10,
        ),
    )


def create_production_auth_config() -> AuthSettings:
    """Create production authentication configuration.

    Returns:
        AuthSettings configured for production.

    """
    return AuthSettings(
        project_name="flext-auth",
        project_version="0.7.0",
        environment="production",
        debug=False,
        database_url="postgresql://localhost/flext_auth_prod",
        database_pool_size=50,
        jwt=JWTConfig(  # type: ignore[call-arg]
            algorithm="RS256",
            access_token_expire_minutes=15,
            refresh_token_expire_days=7,
        ),
        security=SecurityConfig(  # type: ignore[call-arg]
            require_email_verification=True,
            max_failed_login_attempts=3,
            account_lockout_duration_minutes=60,
        ),
        session=SessionConfig(  # type: ignore[call-arg]
            timeout_hours=8,
            max_sessions_per_user=3,
        ),
    )

"""Configuration for FLEXT-AUTH infrastructure.

Using flext-core base settings - NO duplication.
"""

from __future__ import annotations

from datetime import timedelta

from flext_core.domain.pydantic_base import BaseSettings


class AuthConfig(BaseSettings):
    """Authentication service configuration."""

    # JWT settings
    jwt_secret_key: str = "dev-secret-key"
    jwt_public_key_path: str | None = None
    jwt_private_key_path: str | None = None
    jwt_algorithm: str = "HS256"
    jwt_access_token_expire_minutes: int = 30
    jwt_refresh_token_expire_days: int = 7

    # Password settings
    bcrypt_rounds: int = 12
    password_min_length: int = 8
    password_require_uppercase: bool = True
    password_require_lowercase: bool = True
    password_require_numbers: bool = True
    password_require_symbols: bool = False

    # Email verification
    require_email_verification: bool = True
    email_verification_token_expire_hours: int = 24

    # Password reset
    password_reset_token_expire_hours: int = 1

    # Account lockout
    max_failed_login_attempts: int = 5
    account_lockout_duration_minutes: int = 30

    # Session settings
    session_expire_hours: int = 24
    session_extend_on_activity: bool = True

    # Database settings
    database_url: str = "postgresql://localhost/flext_auth"
    database_pool_size: int = 20
    database_max_overflow: int = 40

    # Redis settings (for token storage)
    redis_url: str = "redis://localhost:6379/0"
    redis_max_connections: int = 50
    redis_key_prefix: str = "flext:auth:"

    # SMTP settings
    smtp_host: str = "localhost"
    smtp_port: int = 587
    smtp_username: str = ""
    smtp_password: str = ""
    smtp_use_tls: bool = True
    smtp_use_ssl: bool = False
    from_email: str = "noreply@flext.sh"

    # Security settings
    secure_cookies: bool = True
    same_site_cookies: str = "strict"  # strict, lax, none

    # Rate limiting
    rate_limit_enabled: bool = True
    login_rate_limit_per_minute: int = 10
    registration_rate_limit_per_hour: int = 5

    @property
    def jwt_access_token_expire_delta(self) -> timedelta:
        """Get JWT access token expiration as timedelta.

        Returns:
            Timedelta representing access token lifetime.

        """
        return timedelta(minutes=self.jwt_access_token_expire_minutes)

    @property
    def jwt_refresh_token_expire_delta(self) -> timedelta:
        """Get JWT refresh token expiration as timedelta.

        Returns:
            Timedelta representing refresh token lifetime.

        """
        return timedelta(days=self.jwt_refresh_token_expire_days)

    @property
    def email_verification_token_expire_delta(self) -> timedelta:
        """Get email verification token expiration as timedelta.

        Returns:
            Timedelta representing email verification token lifetime.

        """
        return timedelta(hours=self.email_verification_token_expire_hours)

    @property
    def password_reset_token_expire_delta(self) -> timedelta:
        """Get password reset token expiration as timedelta.

        Returns:
            Timedelta representing password reset token lifetime.

        """
        return timedelta(hours=self.password_reset_token_expire_hours)

    @property
    def account_lockout_duration_delta(self) -> timedelta:
        """Get account lockout duration as timedelta.

        Returns:
            Timedelta representing how long accounts remain locked.

        """
        return timedelta(minutes=self.account_lockout_duration_minutes)

    @property
    def session_expire_delta(self) -> timedelta:
        """Get session expiration as timedelta.

        Returns:
            Timedelta representing session lifetime.

        """
        return timedelta(hours=self.session_expire_hours)

    @property
    def is_jwt_asymmetric(self) -> bool:
        """Check if JWT algorithm uses asymmetric cryptography.

        Returns:
            True if using RSA or ECDSA algorithms, False for HMAC.

        """
        return self.jwt_algorithm.startswith("RS") or self.jwt_algorithm.startswith(
            "ES",
        )

    @property
    def jwt_keys_configured(self) -> bool:
        """Check if JWT keys are properly configured for the algorithm.

        Returns:
            True if required keys are configured, False otherwise.

        """
        if self.is_jwt_asymmetric:
            return (
                self.jwt_public_key_path is not None
                and self.jwt_private_key_path is not None
            )
        return len(self.jwt_secret_key) >= 32

    @property
    def smtp_configured(self) -> bool:
        """Check if SMTP settings are configured for email sending.

        Returns:
            True if SMTP is properly configured, False otherwise.

        """
        return (
            self.smtp_host != "localhost"
            and self.smtp_username != ""
            and self.smtp_password != ""
        )

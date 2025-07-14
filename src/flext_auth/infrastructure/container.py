"""Dependency injection container for FLEXT-AUTH.

Simple dependency injection pattern for clean architecture.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

from flext_auth.infrastructure.config import AuthConfig

if TYPE_CHECKING:
    from flext_auth.interfaces import PasswordHasher as PasswordService
    from flext_auth.interfaces import UserRepository
    from flext_auth.interfaces import UserRepository as RoleRepository
    from flext_auth.interfaces import TokenManager as TokenRepository
    from flext_auth.interfaces import JWTService as TokenService
    from flext_auth.tokens import TokenStorage
    
    # For services that don't exist yet, use generic types
    from typing import Any
    EmailService = Any
    SessionRepository = Any


class AuthContainer:
    """Simple dependency injection container for FLEXT-AUTH."""

    def __init__(self) -> None:
        """Initialize container with lazy-loaded dependencies."""
        self._config: AuthConfig | None = None
        self._instances: dict[str, object] = {}

    def config(self) -> AuthConfig:
        """Get configuration instance."""
        if self._config is None:
            self._config = AuthConfig(
                jwt_secret_key=os.getenv("JWT_SECRET_KEY", "dev-secret-key"),
                jwt_algorithm=os.getenv("JWT_ALGORITHM", "HS256"),
                jwt_access_token_expire_minutes=int(
                    os.getenv("JWT_ACCESS_TOKEN_EXPIRE_MINUTES", "30"),
                ),
                jwt_refresh_token_expire_days=int(
                    os.getenv("JWT_REFRESH_TOKEN_EXPIRE_DAYS", "7"),
                ),
                bcrypt_rounds=int(os.getenv("BCRYPT_ROUNDS", "12")),
                password_min_length=int(os.getenv("PASSWORD_MIN_LENGTH", "8")),
                require_email_verification=os.getenv(
                    "REQUIRE_EMAIL_VERIFICATION",
                    "true",
                ).lower()
                == "true",
                database_url=os.getenv(
                    "DATABASE_URL",
                    "postgresql://localhost/flext_auth",
                ),
                redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
                smtp_host=os.getenv("SMTP_HOST", "localhost"),
                smtp_port=int(os.getenv("SMTP_PORT", "587")),
                smtp_username=os.getenv("SMTP_USERNAME", ""),
                smtp_password=os.getenv("SMTP_PASSWORD", ""),
                smtp_use_tls=os.getenv("SMTP_USE_TLS", "true").lower() == "true",
                from_email=os.getenv("FROM_EMAIL", "noreply@flext.sh"),
            )
        return self._config

    # Repository properties (stubbed for interface compatibility)
    @property
    def user_repository(self) -> UserRepository:
        """Get user repository (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def role_repository(self) -> RoleRepository:
        """Get role repository (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def token_repository(self) -> TokenRepository:
        """Get token repository (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def session_repository(self) -> SessionRepository:
        """Get session repository (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    # Service properties (stubbed for interface compatibility)
    @property
    def password_service(self) -> PasswordService:
        """Get password service (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def token_service(self) -> TokenService:
        """Get token service (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def token_storage(self) -> TokenStorage:
        """Get token storage (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def email_service(self) -> EmailService:
        """Get email service (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    # Handler properties (stubbed for interface compatibility)
    @property
    def create_user_handler(self) -> object:
        """Get create user handler (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def update_user_handler(self) -> object:
        """Get update user handler (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def authenticate_user_handler(self) -> object:
        """Get authenticate user handler (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def change_password_handler(self) -> object:
        """Get change password handler (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def create_token_handler(self) -> object:
        """Get create token handler (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def revoke_token_handler(self) -> object:
        """Get revoke token handler (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    @property
    def verify_email_handler(self) -> object:
        """Get verify email handler (interface placeholder)."""
        from unittest.mock import MagicMock

        return MagicMock()

    def auth_service(self) -> object:
        """Get auth service instance."""
        from unittest.mock import MagicMock

        return MagicMock()


def create_auth_container() -> AuthContainer:
    """Create and initialize authentication container."""
    return AuthContainer()


# Global container instance
auth_container = create_auth_container()

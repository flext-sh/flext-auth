"""Dependency injection container for FLEXT-AUTH.

Simple dependency injection pattern for clean architecture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    # Use real implementations
    from datetime import timedelta

    from flext_auth.application.auth_service import PasswordService
    from flext_auth.domain.repositories import UserRepository
    from flext_auth.infrastructure.config import AuthConfig
    from flext_auth.infrastructure.implementations.authentication_implementation import (
        PlaceholderEmailService,
    )
    from flext_auth.interfaces import (
        PasswordHasher,
        SecurityAuditor,
    )

    # Type alias for email service
    EmailService = PlaceholderEmailService


class AuthContainer:
    """Simple dependency injection container for FLEXT-AUTH."""

    def __init__(self) -> None:
        """Initialize container with lazy-loaded dependencies."""
        self._instances: dict[str, object] = {}

    def config(self) -> AuthConfig:
        """Get configuration instance."""
        if "config" not in self._instances:
            from flext_auth.infrastructure.adapters import create_environment_config
            from flext_auth.infrastructure.config import AuthConfig

            # Use environment adapter internally but return AuthConfig for compatibility
            env_config = create_environment_config("FLEXT_AUTH_")

            # Create AuthConfig from environment using the adapter
            auth_config = AuthConfig(
                jwt_secret_key=env_config.get_string(
                    "jwt_secret_key", "dev-secret-key",
                ),
                auth_algorithm=env_config.get_string("auth_algorithm", "HS256"),
                auth_token_expire_minutes=env_config.get_int(
                    "auth_token_expire_minutes", 30,
                ),
                jwt_refresh_token_expire_days=env_config.get_int(
                    "jwt_refresh_token_expire_days", 7,
                ),
                bcrypt_rounds=env_config.get_int("bcrypt_rounds", 12),
                password_min_length=env_config.get_int("password_min_length", 8),
                require_email_verification=env_config.get_bool(
                    "require_email_verification", True,
                ),
                database_url=env_config.get_string(
                    "database_url", "postgresql://localhost/flext_auth",
                ),
                redis_url=env_config.get_string(
                    "redis_url", "redis://localhost:6379/0",
                ),
                smtp_host=env_config.get_string("smtp_host", "localhost"),
                smtp_port=env_config.get_int("smtp_port", 587),
                smtp_username=env_config.get_string("smtp_username", ""),
                smtp_password=env_config.get_string("smtp_password", ""),
                smtp_use_tls=env_config.get_bool("smtp_use_tls", True),
                from_email=env_config.get_string("from_email", "noreply@flext.sh"),
            )

            self._instances["config"] = auth_config

        from typing import cast

        from flext_auth.config import AuthConfig
        return cast("AuthConfig", self._instances["config"])

    # Repository properties - Real implementations only
    @property
    def user_repository(self) -> UserRepository:
        """Get user repository implementation."""
        if "user_repository" not in self._instances:
            from flext_auth.infrastructure.implementations import (
                EnterpriseUserRepository,
            )

            self._instances["user_repository"] = EnterpriseUserRepository()
        from typing import cast

        return cast("UserRepository", self._instances["user_repository"])

    @property
    def role_repository(self) -> object:
        """Get role repository implementation."""
        if "role_repository" not in self._instances:
            # Placeholder for role repository
            self._instances["role_repository"] = object()
        return self._instances["role_repository"]

    @property
    def token_repository(self) -> object:
        """Get token repository implementation."""
        if "token_repository" not in self._instances:
            # Placeholder for token repository
            self._instances["token_repository"] = object()
        return self._instances["token_repository"]

    @property
    def session_repository(self) -> object:
        """Get session repository implementation."""
        if "session_repository" not in self._instances:
            # Placeholder for session repository
            self._instances["session_repository"] = object()
        return self._instances["session_repository"]

    # Service properties - Real implementations only
    @property
    def password_service(self) -> PasswordHasher:
        """Get password service implementation."""
        if "password_service" not in self._instances:
            from flext_auth.infrastructure.adapters import (
                create_environment_config,
                create_password_hasher,
            )

            # Create password hasher with dependency injection
            config = create_environment_config("FLEXT_AUTH_")
            rounds = config.get_int("bcrypt_rounds", 12)

            create_password_hasher()
            # Note: EnterprisePasswordHasher should be updated to use the adapter
            # For now, we'll create it directly but with proper configuration
            from flext_auth.infrastructure.implementations import (
                EnterprisePasswordHasher,
            )

            self._instances["password_service"] = EnterprisePasswordHasher(
                rounds=rounds,
            )
        from typing import cast
        return cast("object", self._instances["password_service"])

    @property
    def token_service(self) -> Any:
        """Get JWT token service implementation."""
        if "token_service" not in self._instances:
            from flext_auth.infrastructure.adapters import (
                create_filesystem,
                create_jwt_adapter,
                create_logger,
                create_time_provider,
            )
            from flext_auth.infrastructure.jwt import create_jwt_service

            # Create dependency adapters
            jwt_library = create_jwt_adapter()
            # Create a simple config adapter that uses AuthConfig values

            class AuthConfigAdapter:
                def __init__(self, auth_config: AuthConfig) -> None:
                    self._auth_config = auth_config

                def get_string(self, key: str, default: str | None = None) -> str:
                    return getattr(self._auth_config, key, default or "")

                def get_int(self, key: str, default: int | None = None) -> int:
                    return getattr(self._auth_config, key, default or 0)

                def get_bool(self, key: str, default: bool | None = None) -> bool:
                    return getattr(self._auth_config, key, default or False)

                def get_timedelta(self, key: str, default: timedelta | None = None) -> timedelta:
                    from datetime import timedelta as td
                    value = getattr(self._auth_config, key, default)
                    return value if value is not None else td(seconds=0)

            config = AuthConfigAdapter(self.config())
            filesystem = create_filesystem()
            time_provider = create_time_provider()
            logger = create_logger("flext_auth.jwt")

            # Create JWT service with proper dependency injection
            self._instances["token_service"] = create_jwt_service(
                jwt_library=jwt_library,
                config=config,
                filesystem=filesystem,
                time_provider=time_provider,
                logger=logger,
            )
        return self._instances["token_service"]

    @property
    def jwt_service(self) -> Any:
        """Get JWT service implementation."""
        return self.token_service

    @property
    def token_manager(self) -> Any:
        """Get token manager implementation."""
        if "token_manager" not in self._instances:
            from flext_auth.infrastructure.adapters import (
                create_environment_config,
                create_redis_adapter,
            )
            from flext_auth.infrastructure.implementations import EnterpriseTokenManager

            # Create Redis client with dependency injection
            config = create_environment_config("FLEXT_AUTH_")
            redis_url = config.get_string("redis_url", "redis://localhost:6379/0")
            redis_adapter = create_redis_adapter(redis_url)

            # Get JWT service
            jwt_service = self.jwt_service

            self._instances["token_manager"] = EnterpriseTokenManager(
                redis_client=redis_adapter.client,  # Use public property
                jwt_service=jwt_service,
            )
        return self._instances["token_manager"]

    @property
    def token_storage(self) -> object:
        """Get token storage implementation."""
        if "token_storage" not in self._instances:
            from flext_auth.tokens import create_token_storage

            self.config()
            self._instances["token_storage"] = create_token_storage(
                backend="memory",  # For development/testing
            )
        return self._instances["token_storage"]

    @property
    def email_service(self) -> object:
        """Get email service implementation (placeholder)."""
        if "email_service" not in self._instances:
            from flext_auth.infrastructure.implementations import (
                PlaceholderEmailService,
            )

            self._instances["email_service"] = PlaceholderEmailService()
        return self._instances["email_service"]

    @property
    def security_auditor(self) -> SecurityAuditor:
        """Get security auditor implementation."""
        if "security_auditor" not in self._instances:
            from flext_auth.user_service import SecurityAuditorImpl

            self._instances["security_auditor"] = SecurityAuditorImpl()
        from typing import cast
        return cast("object", self._instances["security_auditor"])

    # Handler properties - Real implementations only
    @property
    def create_user_handler(self) -> object:
        """Get create user handler implementation."""
        if "create_user_handler" not in self._instances:
            from typing import cast

            from flext_auth.infrastructure.implementations import CreateUserHandler
            self._instances["create_user_handler"] = CreateUserHandler(
                user_repository=cast("UserRepository", self.user_repository),
                password_service=cast("PasswordService", self.password_service),
            )
        return self._instances["create_user_handler"]

    @property
    def update_user_handler(self) -> object:
        """Get update user handler implementation."""
        if "update_user_handler" not in self._instances:
            from typing import cast

            from flext_auth.infrastructure.implementations import UpdateUserHandler
            self._instances["update_user_handler"] = UpdateUserHandler(
                user_repository=cast("UserRepository", self.user_repository),
            )
        return self._instances["update_user_handler"]

    @property
    def authenticate_user_handler(self) -> object:
        """Get authenticate user handler implementation."""
        if "authenticate_user_handler" not in self._instances:
            from typing import cast

            from flext_auth.infrastructure.implementations import (
                AuthenticateUserHandler,
            )
            self._instances["authenticate_user_handler"] = AuthenticateUserHandler(
                user_repository=cast("UserRepository", self.user_repository),
                password_service=cast("PasswordService", self.password_service),
                token_service=self.token_service,
            )
        return self._instances["authenticate_user_handler"]

    @property
    def change_password_handler(self) -> object:
        """Get change password handler implementation."""
        if "change_password_handler" not in self._instances:
            from typing import cast

            from flext_auth.infrastructure.implementations import ChangePasswordHandler
            self._instances["change_password_handler"] = ChangePasswordHandler(
                user_repository=cast("UserRepository", self.user_repository),
                password_service=cast("PasswordService", self.password_service),
            )
        return self._instances["change_password_handler"]

    @property
    def create_token_handler(self) -> object:
        """Get create token handler implementation."""
        if "create_token_handler" not in self._instances:
            from typing import cast

            from flext_auth.infrastructure.implementations import CreateTokenHandler
            self._instances["create_token_handler"] = CreateTokenHandler(
                user_repository=cast("UserRepository", self.user_repository),
                token_service=self.token_service,
            )
        return self._instances["create_token_handler"]

    @property
    def revoke_token_handler(self) -> object:
        """Get revoke token handler implementation."""
        if "revoke_token_handler" not in self._instances:
            from flext_auth.infrastructure.implementations import RevokeTokenHandler

            self._instances["revoke_token_handler"] = RevokeTokenHandler(
                token_service=self.token_service,
            )
        return self._instances["revoke_token_handler"]

    @property
    def verify_email_handler(self) -> object:
        """Get verify email handler implementation."""
        if "verify_email_handler" not in self._instances:
            from typing import cast

            from flext_auth.infrastructure.implementations import VerifyEmailHandler
            self._instances["verify_email_handler"] = VerifyEmailHandler(
                user_repository=cast("UserRepository", self.user_repository),
                email_service=cast("EmailService", self.email_service),
            )
        return self._instances["verify_email_handler"]

    @property
    def user_service(self) -> Any:
        """Get user service implementation."""
        if "user_service" not in self._instances:
            from flext_auth.user_service import UserService

            self._instances["user_service"] = UserService(
                user_repository=self.user_repository,
                password_hasher=self.password_service,
                jwt_service=self.jwt_service,
                token_manager=self.token_manager,
                security_auditor=self.security_auditor,
            )
        return self._instances["user_service"]

    @property
    def auth_service(self) -> object:
        """Get authentication service implementation."""
        if "auth_service" not in self._instances:
            from flext_auth.application.command_auth_service import AuthService

            self._instances["auth_service"] = AuthService(
                user_service=self.user_service,
                jwt_service=self.jwt_service,
                token_manager=self.token_manager,
            )
        return self._instances["auth_service"]


def create_auth_container() -> AuthContainer:
    """Create and initialize authentication container."""
    return AuthContainer()


# Global container instance
auth_container = create_auth_container()

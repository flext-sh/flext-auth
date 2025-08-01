"""FLEXT Auth - Enterprise Authentication Library.

Biblioteca pura para autenticação com interface única.
Todas as funcionalidades acessíveis APENAS através desta raiz.

Base: flext-core patterns para máxima reutilização.
Prefixos: FlextAuth* para classes, flext_auth_* para helpers.

Refatorado: Módulos especializados seguindo Single Responsibility Principle.
"""

from __future__ import annotations

import asyncio
import importlib.metadata

# Import FlextResult for public interface
from flext_core import FlextResult

# Import dependencies object for parameter object pattern
# Core classes and services
# Import auth service config for FlextAuth constructor
from flext_auth.auth import (
    FlextAuthService,
    FlextAuthServiceConfig,
    FlextAuthServiceDependencies,
    FlextUserRegistrationData,
)
from flext_auth.config import (
    DEFAULT_DEV_SECRET,
    DEFAULT_JWT_SECRET,
    DEFAULT_MFA_SECRET,
    DEFAULT_SERVICE_SECRET,
    FlextAuthConfig,
)

# Core exports from specialized modules
from flext_auth.decorators import (
    flext_auth_permission_required,
    flext_auth_required,
    flext_auth_role_required,
)
from flext_auth.domain.entities import FlextUser, FlextUserRole

# Exception classes
from flext_auth.exceptions import (
    FlextAuthConfigurationError,
    FlextAuthError,
    FlextAuthPermissionError,
    FlextAuthSecurityError,
    FlextAuthValidationError,
)
from flext_auth.helpers import (
    ADMIN_ROLE,
    API_CONFIG,
    FAST_CONFIG,
    GUEST_ROLE,
    HTTP_FORBIDDEN,
    HTTP_UNAUTHORIZED,
    MODERATOR_ROLE,
    PRODUCTION_CONFIG,
    USER_ROLE,
    WEB_CONFIG,
    AuthResult,
    FlextAuthBatchOperations,
    FlextAuthClaims,
    FlextAuthHeaders,
    FlextAuthPermissions,
    FlextAuthRole,
    FlextAuthSessionData,
    FlextAuthSessionMixin,
    FlextAuthTokenData,
    FlextAuthUser,
    FlextAuthUserData,
    PermissionSet,
    RoleHierarchy,
    SessionData,
    TokenData,
    UserData,
    flext_auth_api,
    flext_auth_batch_operations,
    flext_auth_build_response,
    flext_auth_check_token,
    flext_auth_complete_workflow,
    flext_auth_create_api_key,
    flext_auth_create_auth_context,
    flext_auth_create_multi_factor_token,
    flext_auth_create_role_hierarchy,
    flext_auth_create_secure_session,
    flext_auth_create_service_token,
    flext_auth_create_user_payload,
    flext_auth_decode_jwt,
    flext_auth_dev,
    flext_auth_extract_token_claims,
    flext_auth_extract_user_context,
    flext_auth_filter_user_data,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_instant_api,
    flext_auth_merge_configs,
    flext_auth_middleware_factory,
    flext_auth_one_liner,
    flext_auth_prod,
    flext_auth_quick_start,
    flext_auth_rate_limit,
    flext_auth_validate_api_key,
    flext_auth_validate_email,
    flext_auth_validate_jwt,
    flext_auth_validate_password_strength,
    flext_auth_validate_permissions,
    flext_auth_validate_username,
    flext_auth_verify_password,
    flext_auth_web,
)
from flext_auth.jwt import FlextJWTService
from flext_auth.mixins import FlextAuthMixin, FlextAuthUserMixin
from flext_auth.services.password_service import FlextPasswordService
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository
from flext_auth.utils import convert_user_to_dict

# Version information
try:
    __version__ = importlib.metadata.version("flext-auth")
except importlib.metadata.PackageNotFoundError:
    __version__ = "0.9.0"

__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# Legacy constants for backward compatibility
FLEXT_AUTH_ADMIN = ADMIN_ROLE
FLEXT_AUTH_USER = USER_ROLE
FLEXT_AUTH_GUEST = GUEST_ROLE


class FlextAuthSetupError(FlextAuthError):  # type: ignore[valid-type,misc]
    """Exception raised during FlextAuth setup operations."""


# =============================================================================
# SOLID REFACTORING: DRY Principle - centralized in utils.py module
# =============================================================================


# Main FlextAuth class - simplified interface
class FlextAuth:
    """Main FlextAuth class providing unified authentication interface.

    Simplified version that composes functionality from specialized services.
    """

    def __init__(
        self,
        config: FlextAuthConfig | None = None,
        **config_overrides: object,
    ) -> None:
        """Initialize FlextAuth with configuration.

        Args:
            config: FlextAuthConfig instance
            **config_overrides: Configuration overrides

        """
        if config is None:
            config_data = {**FAST_CONFIG, **config_overrides}
            config = FlextAuthConfig(**config_data)

        self._config = config

        # Initialize dependencies
        self._user_repository = InMemoryUserRepository()
        self._session_repository = InMemorySessionRepository()
        self._password_service = FlextPasswordService(rounds=config.bcrypt_rounds)
        self._jwt_service = FlextJWTService(secret_key=config.jwt_secret_key)

        # Initialize auth service with all dependencies
        auth_config = FlextAuthServiceConfig(
            max_failed_attempts=5,
            lockout_duration_minutes=30,
            session_expire_hours=24,
            max_concurrent_sessions=5,
        )

        # Create dependencies object using Parameter Object Pattern
        dependencies = FlextAuthServiceDependencies(
            user_repository=self._user_repository,
            session_repository=self._session_repository,
            password_service=self._password_service,
            jwt_service=self._jwt_service,
            config=auth_config,
        )
        self._auth_service = FlextAuthService(dependencies)

    @property
    def config(self) -> FlextAuthConfig:
        """Get current configuration."""
        return self._config

    @property
    def auth_service(self) -> FlextAuthService:
        """Get auth service instance."""
        return self._auth_service

    @property
    def jwt_service(self) -> FlextJWTService:
        """Get JWT service instance."""
        return self._jwt_service

    @property
    def password_service(self) -> FlextPasswordService:
        """Get password service instance."""
        return self._password_service

    @property
    def user_repository(self) -> InMemoryUserRepository:
        """Get user repository instance."""
        return self._user_repository

    @property
    def session_repository(self) -> InMemorySessionRepository:
        """Get session repository instance."""
        return self._session_repository

    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str = "127.0.0.1",
        user_agent: str | None = None,
    ) -> AuthResult:
        """Authenticate user with username and password."""

        async def _auth() -> FlextResult[dict[str, object]]:
            return await self._auth_service.authenticate_user(
                username,
                password,
                ip_address,
                user_agent,
            )

        result = asyncio.run(_auth())
        if result.is_success and result.data:
            return result.data
        return {"error": result.error or "Authentication failed"}

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "USER",
        **context: object,
    ) -> AuthResult:
        """Register new user."""
        # Convert role string to enum
        role_enum = getattr(FlextUserRole, role.upper(), FlextUserRole.USER)

        # Extract context with defaults
        ip_address = str(context.get("ip_address", "127.0.0.1"))
        user_agent = context.get("user_agent")
        user_agent_str = str(user_agent) if user_agent is not None else None

        registration_data = FlextUserRegistrationData(
            username=username,
            email=email,
            password=password,
            role=role_enum,
            ip_address=ip_address,
            user_agent=user_agent_str,
        )

        async def _register() -> FlextResult[FlextUser]:
            return await self._auth_service.register_user(registration_data)

        result = asyncio.run(_register())
        if result.is_success and result.data:
            # SOLID REFACTORING: Use DRY principle - centralized user conversion
            return convert_user_to_dict(result.data)
        return {"error": result.error or "Registration failed"}

    def validate_token(self, token: str) -> AuthResult:
        """Validate JWT token."""
        result = self._jwt_service.verify_token(token)
        if result.is_success and result.data:
            return {"valid": True, "claims": result.data.__dict__}
        return {"error": result.error or "Token validation failed"}

    def generate_token(self, user_data: UserData) -> str | None:
        """Generate JWT token for user."""
        # Extract required fields from user_data
        user_id = str(user_data.get("id", ""))
        username = str(user_data.get("username", ""))
        role = str(user_data.get("role", "USER"))

        if not user_id or not username:
            return None

        result = self._jwt_service.generate_access_token(
            user_id=user_id,
            username=username,
            role=role,
        )
        return result.data if result.is_success else None

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        result = self._password_service.hash_password(password)
        if result.is_success and result.data:
            return str(result.data)
        return ""

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        result = self._password_service.verify_password(password, hashed)
        if result.is_success and result.data is not None:
            return bool(result.data)
        return False


# Additional domain classes with composition
# FlextAuthUser is deprecated - removed to eliminate NotImplementedError smell
# Use FlextUser directly from flext_auth.domain.entities
# This eliminates dead code and follows SOLID principles


# Factory functions remain available for backward compatibility
def create_flext_auth(**config_overrides: object) -> FlextAuth:
    """Create FlextAuth instance with optional configuration overrides."""
    # Convert object kwargs to proper config
    config = None
    if config_overrides:
        try:
            # Try to create FlextAuthConfig from overrides
            config_dict = {k: v for k, v in config_overrides.items() if v is not None}
            config = FlextAuthConfig(**config_dict)
        except (TypeError, ValueError):
            # Fall back to default config
            config = None

    return FlextAuth(config=config)


# Comprehensive public API - sorted alphabetically
__all__ = [
    "ADMIN_ROLE",
    "API_CONFIG",
    "DEFAULT_DEV_SECRET",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_MFA_SECRET",
    "DEFAULT_SERVICE_SECRET",
    "FAST_CONFIG",
    "FLEXT_AUTH_ADMIN",
    "FLEXT_AUTH_GUEST",
    "FLEXT_AUTH_USER",
    "GUEST_ROLE",
    "HTTP_FORBIDDEN",
    "HTTP_UNAUTHORIZED",
    "MODERATOR_ROLE",
    "PRODUCTION_CONFIG",
    "USER_ROLE",
    "WEB_CONFIG",
    "AuthResult",
    "FlextAuth",
    "FlextAuthBatchOperations",
    "FlextAuthClaims",
    "FlextAuthConfig",
    "FlextAuthConfigurationError",
    "FlextAuthError",
    "FlextAuthHeaders",
    "FlextAuthMixin",
    "FlextAuthPermissionError",
    "FlextAuthPermissions",
    "FlextAuthRole",
    "FlextAuthSecurityError",
    "FlextAuthService",
    "FlextAuthSessionData",
    "FlextAuthSessionMixin",
    "FlextAuthSetupError",
    "FlextAuthTokenData",
    "FlextAuthUser",
    "FlextAuthUserData",
    "FlextAuthUserMixin",
    "FlextAuthValidationError",
    "FlextJWTService",
    "FlextPasswordService",
    "FlextResult",
    "FlextUser",
    "FlextUserRole",
    "InMemorySessionRepository",
    "InMemoryUserRepository",
    "PermissionSet",
    "RoleHierarchy",
    "SessionData",
    "TokenData",
    "UserData",
    "__version__",
    "__version_info__",
    "create_flext_auth",
    "flext_auth_api",
    "flext_auth_batch_operations",
    "flext_auth_build_response",
    "flext_auth_check_token",
    "flext_auth_complete_workflow",
    "flext_auth_create_api_key",
    "flext_auth_create_auth_context",
    "flext_auth_create_multi_factor_token",
    "flext_auth_create_role_hierarchy",
    "flext_auth_create_secure_session",
    "flext_auth_create_service_token",
    "flext_auth_create_user_payload",
    "flext_auth_decode_jwt",
    "flext_auth_dev",
    "flext_auth_extract_token_claims",
    "flext_auth_extract_user_context",
    "flext_auth_filter_user_data",
    "flext_auth_generate_jwt",
    "flext_auth_hash_password",
    "flext_auth_instant_api",
    "flext_auth_merge_configs",
    "flext_auth_middleware_factory",
    "flext_auth_one_liner",
    "flext_auth_permission_required",
    "flext_auth_prod",
    "flext_auth_quick_start",
    "flext_auth_rate_limit",
    "flext_auth_required",
    "flext_auth_role_required",
    "flext_auth_validate_api_key",
    "flext_auth_validate_email",
    "flext_auth_validate_jwt",
    "flext_auth_validate_password_strength",
    "flext_auth_validate_permissions",
    "flext_auth_validate_username",
    "flext_auth_verify_password",
    "flext_auth_web",
]

# Metadata
__architecture__ = "Clean Architecture + DDD + Specialized Modules"
__purpose__ = "Authentication with maximum code reduction via composition"
__access_pattern__ = "Root namespace with specialized module composition"
__refactoring__ = "Reduced from 1929 lines to ~250 lines via modularization"

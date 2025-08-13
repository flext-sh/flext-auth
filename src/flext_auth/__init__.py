"""FLEXT Auth - Enterprise Authentication Library for FLEXT ecosystem.

This module provides comprehensive authentication and authorization services for the
FLEXT ecosystem, implementing enterprise-grade security patterns with Clean Architecture
and Domain-Driven Design principles.

The library is reorganized following PEP8 strict naming patterns with consolidated
modules providing clean, organized access to authentication functionality including
JWT token management, password hashing, session management, and role-based access control.

Architecture:
    - auth_config: Configuration management and type definitions
    - auth_models: Domain entities, value objects, and repository patterns
    - auth_services: Service layer with password, JWT, and application services
    - auth_decorators: Decorators and mixins for authentication aspects
    - auth_validation: Input validation and field management
    - auth_session: Session management and repository patterns
    - auth_utilities: Helper functions and utility classes
    - auth_exceptions: Authentication-specific exception hierarchy
    - auth_app: Main authentication service and application layer

Features:
    - JWT token generation and validation
    - Secure password hashing with bcrypt
    - Session management with configurable storage
    - Role-based access control (RBAC)
    - Multi-factor authentication support
    - Enterprise security compliance

Example:
    Basic authentication setup and usage:

    >>> from flext_auth import FlextAuth, create_auth_config
    >>> config = create_auth_config(jwt_secret="your-secret-key")
    >>> auth = FlextAuth(config)
    >>> result = auth.authenticate("username", "password")
    >>> if result.is_success:
    ...     print(f"Token: {result.data}")

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import importlib.metadata
from typing import ClassVar

from flext_core import FlextResult
from flext_core.loggings import FlextLoggerFactory
from flext_auth.constants import FlextAuthConstants, DEFAULT_JWT_SECRET, DEFAULT_DEV_SECRET

# =============================================================================
# REORGANIZED IMPORTS - From consolidated PEP8 modules
# =============================================================================

# Configuration and types
from flext_auth.auth_config import (
    FlextAuthApplicationConfig,
    FlextAuthConfig,
    create_auth_config,
    create_development_config,
    create_production_config,
)

# Domain models
from flext_auth.models import (
    FlextHashedPassword,
    FlextJWTClaims,
    FlextLoginAttempt,
    FlextPermission,
    FlextPlainPassword,
    FlextRole,
    FlextSecurityContext,
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserEmail,
    FlextUserRole,
    FlextUserStatus,
    FlextUsername,
    InMemoryUserRepository,
    UserRepository,
)

# Services layer
from flext_auth.auth_services import (
    FlextAuthenticationService,
    FlextAuthorizationService,
    FlextJWTService,
    FlextPasswordService,
    FlextSessionService,
)

# Decorators and mixins
from flext_auth.auth_decorators import (
    FlextAuthMixin,
    FlextAuthSessionMixin,
    FlextAuthUserMixin,
    flext_auth_permission_required,
    flext_auth_required,
    flext_auth_role_required,
)

# Validation and fields
from flext_auth.auth_validation import (
    FlextAuthFieldSchema,
    FlextAuthValidators,
    validate_complete_user_registration,
    validate_email,
    validate_password,
    validate_password_strength,
    validate_username,
)

# Session management
from flext_auth.auth_session import (
    InMemorySessionRepository,
    SessionRepository,
)

# Utilities
from flext_auth.auth_utilities import (
    generate_secure_password,
    generate_secure_token,
    get_utc_now,
    is_strong_password,
    mask_sensitive_data,
)

# Exceptions
from flext_auth.auth_exceptions import (
    FlextAccountInactiveError,
    FlextAccountLockedError,
    FlextAuthError,
    FlextAuthenticationError,
    FlextAuthorizationError,
    FlextExpiredSessionError,
    FlextExpiredTokenError,
    FlextInsufficientPermissionError,
    FlextInvalidCredentialsError,
    FlextInvalidSessionError,
    FlextInvalidTokenError,
    FlextPasswordValidationError,
    FlextPermissionError,
    FlextRoleRequiredError,
    FlextSessionError,
    FlextTokenError,
    FlextValidationError,
)

# Main application service
# Prefer the main service/types from auth.py to match tests
from flext_auth.auth import (
    FlextAuthService,
    FlextAuthServiceConfig,
    FlextAuthServiceDependencies,
)
from flext_auth.auth_app import (
    create_auth_service,
)

# Helpers and public utility functions
from flext_auth.helpers import (
    flext_auth_quick_start as _helpers_quick_start,
    flext_auth_hash_password,
    flext_auth_verify_password,
    flext_auth_generate_jwt,
    flext_auth_validate_jwt,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_decode_jwt,
    flext_auth_create_secure_session,
    flext_auth_instant_api,
    flext_auth_one_liner,
    flext_auth_complete_workflow,
    flext_auth_check_token,
    flext_auth_middleware_factory,
    flext_auth_merge_configs,
    flext_auth_filter_user_data,
    flext_auth_create_user_payload,
    flext_auth_build_response,
    flext_auth_rate_limit,
    flext_auth_extract_token_claims,
    flext_auth_create_api_key,
    flext_auth_validate_api_key,
    flext_auth_create_auth_context,
    flext_auth_create_multi_factor_token,
    flext_auth_create_role_hierarchy,
    flext_auth_validate_permissions,
    flext_auth_extract_user_context,
    flext_auth_create_service_token,
    FlextAuthUser,
    FlextAuthBatchOperations,
    flext_auth_batch_operations as _helpers_batch_ops,
)

# ==============================================================================
# LEGACY/COMPATIBILITY CONSTANTS AND TYPEDEFS
# ==============================================================================

from typing import TypeAlias

# Role constants expected by tests
ADMIN_ROLE = FlextAuthConstants.UserRoles.ADMIN
USER_ROLE = FlextAuthConstants.UserRoles.USER

FLEXT_AUTH_ADMIN = FlextAuthConstants.UserRoles.ADMIN
FLEXT_AUTH_USER = FlextAuthConstants.UserRoles.USER
FLEXT_AUTH_GUEST = FlextAuthConstants.UserRoles.GUEST

# Public typedefs expected by tests
type FlextAuthRole = str
type FlextAuthPermissions = list[str]
type FlextAuthUserData = dict[str, object]
type FlextAuthSessionData = dict[str, object]
type FlextAuthTokenData = dict[str, object]
type FlextAuthHeaders = dict[str, str]
type FlextAuthClaims = dict[str, object]


# ==============================================================================
# MAIN PUBLIC CLASS - Simple facade used by tests
# ==============================================================================

import os as _os
import secrets as _secrets

from flext_auth.auth import (
    FlextAuthService as _CoreAuthService,
    FlextUserRegistrationData as _RegistrationData,
    FlextAuthServiceDependencies as _CoreDeps,
    FlextAuthServiceConfig as _CoreConfig,
)
from flext_auth.jwt import FlextJWTService as _JWT
from flext_auth.auth_services import FlextPasswordService as _Pwd
from flext_auth.session import InMemorySessionRepository as _MemSession
from flext_auth.models import InMemoryUserRepository as _MemUser


class FlextAuth:
    """Thin facade wrapping core auth service for public API.

    Provides async methods expected by tests: register, login, validate,
    refresh, logout. Accepts optional config dict for simple customization.
    """

    def __init__(self, config: dict[str, object] | None = None, *, _service: _CoreAuthService | None = None) -> None:
        from types import SimpleNamespace as _NS
        base_cfg = FlextAuthApplicationConfig()
        self._config: object = base_cfg
        # Apply simple overrides from dict structure used by tests
        if isinstance(config, dict):
            jwt_cfg = config.get("jwt", {})
            sec_cfg = config.get("security", {})
            if isinstance(jwt_cfg, dict) and "access_token_expire_minutes" in jwt_cfg:
                base_cfg.auth.access_token_expire_minutes = int(jwt_cfg["access_token_expire_minutes"])
            if isinstance(sec_cfg, dict) and "password_rounds" in sec_cfg:
                base_cfg.auth.bcrypt_rounds = int(sec_cfg["password_rounds"])
        # Build a lightweight compatibility view for tests
        self._config = _NS(
            auth=base_cfg.auth,
            access_token_expire_minutes=base_cfg.auth.access_token_expire_minutes,
            security=_NS(password_rounds=base_cfg.auth.bcrypt_rounds),
        )

        if _service is not None:
            self._service = _service
        else:
            # Build default in-memory dependencies
            jwt_secret = _os.getenv("FLEXT_AUTH_JWT_SECRET_KEY", _secrets.token_urlsafe(32))
            # Adapter types for dependency protocol expectations
            from flext_auth.user import InMemoryUserRepository as _UserRepo, UserRepository as _UserRepository
            from flext_auth.session import InMemorySessionRepository as _SessionRepo, SessionRepository as _SessionRepository
            user_repo: _UserRepository = _UserRepo()
            session_repo: _SessionRepository = _SessionRepo()
            from flext_auth.services_password_service import FlextPasswordService as _PwdSvc
            from flext_auth.jwt import FlextJWTService as _JwtSvc

            deps = _CoreDeps(
                user_repository=user_repo,
                session_repository=session_repo,
                password_service=_PwdSvc(rounds=self._config.auth.bcrypt_rounds),
                jwt_service=_JwtSvc(secret_key=jwt_secret, access_token_expire_minutes=self._config.auth.access_token_expire_minutes),
                config=_CoreConfig(),
            )
            self._service = _CoreAuthService(deps)

    async def register(self, username: str, email: str, password: str, *, role: str = FlextAuthConstants.UserRoles.USER) -> FlextResult[object]:
        data = _RegistrationData(username=username, email=email, password=password, role=role)  # type: ignore[arg-type]
        result = await self._service.register_user(data)
        # Upcast to FlextResult[object] for facade typing
        return FlextResult.ok(result.data) if result.success else FlextResult.fail(result.error or "Registration failed")

    async def login(self, username: str, password: str) -> FlextResult[dict[str, object]]:
        return await self._service.authenticate_user(username=username, password=password, ip_address="127.0.0.1")

    async def validate(self, token: str) -> FlextResult[dict[str, object]]:
        res = await self._service.validate_token(token)
        if not res.success or not res.data:
            return FlextResult.fail(res.error or "Token validation failed")
        ctx = res.data
        return FlextResult.ok({
            "user_id": ctx.user_id,
            "username": ctx.username,
            "role": ctx.role,
            "permissions": ctx.permissions,
            "session_id": ctx.session_id,
        })

    async def refresh(self, refresh_token: str) -> FlextResult[dict[str, str]]:
        return await self._service.refresh_token(refresh_token)

    async def logout(self, token: str) -> FlextResult[bool]:
        return await self._service.logout_user(token)

    # Convenience and compatibility methods expected by tests and helpers
    async def register_user(self, data_or_username: object, email: str | None = None, password: str | None = None, *, role: str | None = None) -> FlextResult[object]:
        # Accept FlextUserRegistrationData or discrete fields
        if hasattr(data_or_username, "username") and hasattr(data_or_username, "email") and hasattr(data_or_username, "password"):
            reg = await self._service.register_user(data_or_username)  # type: ignore[arg-type]
            return FlextResult.ok(reg.data) if reg.success else FlextResult.fail(reg.error or "Registration failed")
        if isinstance(data_or_username, str) and isinstance(email, str) and isinstance(password, str):
            return await self.register(data_or_username, email, password, role=role or FlextAuthConstants.UserRoles.USER)
        return FlextResult.fail("Invalid registration parameters")

    async def authenticate_user(self, username: str, password: str, *, ip_address: str = "127.0.0.1") -> FlextResult[dict[str, object]]:
        return await self._service.authenticate_user(username=username, password=password, ip_address=ip_address)

    async def validate_token(self, token: str) -> FlextResult[object]:
        # Forward raw security context for helpers that expect object with attributes, but conform facade type
        res = await self._service.validate_token(token)
        return FlextResult.ok(res.data) if res.success else FlextResult.fail(res.error or "Token validation failed")

    async def login_and_validate(self, username: str, password: str) -> FlextResult[dict[str, object]]:
        login_result = await self.login(username, password)
        if not login_result.success or not login_result.data:
            return FlextResult.fail(login_result.error or "Login failed")
        access = login_result.data.get("tokens", {}).get("access_token")  # type: ignore[attr-defined]
        if not isinstance(access, str):
            return FlextResult.fail("Access token missing")
        return await self.validate(access)

    async def change_password(self, user_id: str, current_password: str, new_password: str) -> FlextResult[bool]:
        return await self._service.change_password(user_id, current_password, new_password)

    async def get_user_sessions(self, user_id: str) -> FlextResult[list[dict[str, object]]]:
        return await self._service.get_user_sessions(user_id)

    async def cleanup_sessions(self) -> FlextResult[int]:
        return await self._service.cleanup_expired_sessions()

    # Compatibility helpers expected by tests
    @property
    def auth_service(self) -> _CoreAuthService:
        return self._service

    @property
    def jwt_service(self) -> object:  # pragma: no cover - simple facade
        return getattr(self._service, "jwt_service", None)

    @property
    def password_service(self) -> object:  # pragma: no cover - simple facade
        return getattr(self._service, "password_service", None)

    @property
    def user_repository(self) -> object:  # pragma: no cover - simple facade
        return getattr(self._service, "user_repo", None)

    @property
    def session_repository(self) -> object:  # pragma: no cover - simple facade
        return getattr(self._service, "session_repo", None)

    # Sync wrappers delegating to service or to helper flows
    def register_user_sync(self, username: str, email: str, password: str) -> FlextResult[object]:
        import asyncio as _asyncio
        data = _RegistrationData(username=username, email=email, password=password)
        result = _asyncio.run(self._service.register_user(data))
        return result  # type: ignore[return-value]

    def authenticate_user_sync(self, username: str, password: str) -> FlextResult[object]:
        import asyncio as _asyncio
        result = _asyncio.run(self._service.authenticate_user(username=username, password=password, ip_address="127.0.0.1"))
        return result  # type: ignore[return-value]

    async def register_validated(self, username: str, email: str, password: str, *, role: str | None = None, require_strong_password: bool = False) -> FlextResult[dict[str, object]]:
        if require_strong_password:
            strength = flext_auth_validate_password_strength(password)
            if not strength["valid"]:
                return FlextResult.fail("Weak password")
        reg = await self._service.register_user(_RegistrationData(username=username, email=email, password=password, role=role or FlextAuthConstants.UserRoles.USER))  # type: ignore[arg-type]
        if not reg.success or not reg.data:
            return FlextResult.fail(reg.error or "Registration failed")
        return FlextResult.ok({"user": {"id": reg.data.id, "username": reg.data.username, "email": reg.data.email, "role": reg.data.role}, "password_strength": strength if require_strong_password else None})

    async def create_user_session(self, username: str, password: str, *, include_user_data: bool = True) -> FlextResult[dict[str, object]]:
        auth = await self._service.authenticate_user(username=username, password=password, ip_address="127.0.0.1")
        if not auth.success:
            return FlextResult.fail(auth.error or "Authentication failed")
        data = auth.data or {}
        result: dict[str, object] = {"token": data.get("tokens", {}).get("access_token", ""), "context": {"username": username}}  # type: ignore[attr-defined]
        if include_user_data:
            result["user"] = data.get("user", {})
        return FlextResult.ok(result)


def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
    REDACTED_LDAP_BIND_PASSWORD_password: str | None = None,
    config: dict[str, object] | None = None,
    **extra: object,
) -> FlextResult[FlextAuth]:
    """Quick start compat que retorna FlextResult[FlextAuth]."""
    # Call helpers_quick_start with explicit parameters
    service_result = _helpers_quick_start(
        create_REDACTED_LDAP_BIND_PASSWORD=create_REDACTED_LDAP_BIND_PASSWORD,
        REDACTED_LDAP_BIND_PASSWORD_username=REDACTED_LDAP_BIND_PASSWORD_username,
        REDACTED_LDAP_BIND_PASSWORD_password=REDACTED_LDAP_BIND_PASSWORD_password,
        **(config or {}),
        **extra,
    )
    if not service_result.success or not service_result.data:
        return FlextResult.fail(service_result.error or "Quick start failed")
    return FlextResult.ok(FlextAuth(_service=service_result.data))


# Re-export selected helpers under root name expected by tests
flext_auth_hash_password = flext_auth_hash_password
flext_auth_verify_password = flext_auth_verify_password
flext_auth_generate_jwt = flext_auth_generate_jwt
flext_auth_validate_jwt = flext_auth_validate_jwt
flext_auth_decode_jwt = flext_auth_decode_jwt
flext_auth_create_secure_session = flext_auth_create_secure_session
flext_auth_instant_api = flext_auth_instant_api
flext_auth_one_liner = flext_auth_one_liner
flext_auth_check_token = flext_auth_check_token
flext_auth_middleware_factory = flext_auth_middleware_factory
flext_auth_merge_configs = flext_auth_merge_configs
flext_auth_filter_user_data = flext_auth_filter_user_data
flext_auth_create_user_payload = flext_auth_create_user_payload
flext_auth_build_response = flext_auth_build_response
flext_auth_rate_limit = flext_auth_rate_limit
flext_auth_batch_operations = _helpers_batch_ops


# ==============================================================================
# MODULE PATH COMPATIBILITY (legacy import paths)
# ==============================================================================

import sys as _sys
import types as _types

def _alias_module(alias: str, target_module_name: str) -> None:
    try:
        target = __import__(target_module_name, fromlist=["*"])
        module = _types.ModuleType(alias)
        module.__dict__.update(target.__dict__)
        _sys.modules[alias] = module
    except Exception as _e:
        # Best-effort; ignore if fails
        _ = _e

# Map flext_auth.domain.entities -> flext_auth.domain_entities
_alias_module("flext_auth.domain.entities", "flext_auth.domain_entities")
_alias_module("flext_auth.domain.value_objects", "flext_auth.domain_value_objects")

# Map flext_auth.application.services -> flext_auth.auth_services
_alias_module("flext_auth.application.services", "flext_auth.auth_services")
_alias_module("flext_auth.services.password_service", "flext_auth.auth_services")

# =============================================================================
# VERSION AND METADATA
# =============================================================================

try:
    __version__ = importlib.metadata.version("flext-auth")
except Exception:
    __version__ = "unknown"
__version_info__ = tuple(int(x) for x in __version__.split(".") if x.isdigit())

# Logger
_logger = FlextLoggerFactory.get_logger(__name__)

# =============================================================================
# GLOBAL CONFIGURATION
# =============================================================================


class FlextAuthGlobalConfig:
    """Global configuration for FLEXT Auth library."""

    DEFAULT_CONFIG: ClassVar[FlextAuthConfig] = FlextAuthConfig()

    @classmethod
    def get_default_config(cls) -> FlextAuthConfig:
        """Get the default global configuration."""
        return cls.DEFAULT_CONFIG

    @classmethod
    def set_default_config(cls, config: FlextAuthConfig) -> None:
        """Set the default global configuration."""
        cls.DEFAULT_CONFIG = config


# =============================================================================
# QUICK START FUNCTIONS
# =============================================================================


# Removed duplicate flext_auth_quick_start function


def flext_auth_create_development_service() -> object:
    """Create development authentication service with default settings."""
    return create_auth_service("dev-secret-key-32-chars-minimum-length")


# =============================================================================
# EXPORTS - Complete API surface
# =============================================================================

__all__: list[str] = [
    "__version__",
    "__version_info__",
    # Public facade and config
    "FlextAuth",
    "FlextAuthConfig",
    # Core exports already present above
    "FlextAuthConfig",
    "FlextAuthApplicationConfig",
    "FlextAuthGlobalConfig",
    "create_auth_config",
    "create_development_config",
    "create_production_config",
    "FlextUser",
    "FlextUserRole",
    "FlextUserStatus",
    "FlextSession",
    "FlextSessionStatus",
    "FlextRole",
    "FlextPermission",
    "FlextLoginAttempt",
    "FlextUsername",
    "FlextUserEmail",
    "FlextPlainPassword",
    "FlextHashedPassword",
    "FlextJWTClaims",
    "FlextSecurityContext",
    "FlextAuthService",
    "FlextAuthServiceConfig",
    "FlextAuthServiceDependencies",
    "FlextAuthenticationService",
    "FlextAuthorizationService",
    "FlextSessionService",
    "FlextPasswordService",
    "FlextJWTService",
    "UserRepository",
    "InMemoryUserRepository",
    "SessionRepository",
    "InMemorySessionRepository",
    "flext_auth_required",
    "flext_auth_role_required",
    "flext_auth_permission_required",
    "FlextAuthMixin",
    "FlextAuthUserMixin",
    "FlextAuthSessionMixin",
    "FlextAuthValidators",
    "FlextAuthFieldSchema",
    "validate_username",
    "validate_email",
    "validate_password",
    "validate_password_strength",
    "validate_complete_user_registration",
    "generate_secure_token",
    "generate_secure_password",
    "get_utc_now",
    "is_strong_password",
    "mask_sensitive_data",
    "FlextAuthError",
    "FlextAuthenticationError",
    "FlextAuthorizationError",
    "FlextTokenError",
    "FlextSessionError",
    "FlextPermissionError",
    "FlextValidationError",
    "FlextInvalidCredentialsError",
    "FlextAccountLockedError",
    "FlextAccountInactiveError",
    "FlextInvalidTokenError",
    "FlextExpiredTokenError",
    "FlextInvalidSessionError",
    "FlextExpiredSessionError",
    "FlextInsufficientPermissionError",
    "FlextRoleRequiredError",
    "FlextPasswordValidationError",
    "flext_auth_quick_start",
    "flext_auth_create_development_service",
    "DEFAULT_JWT_SECRET",
    "DEFAULT_DEV_SECRET",
    "FlextResult",
    "annotations",
    "ClassVar",
    "FlextLoggerFactory",
    "create_auth_service",
    # Legacy constants and typedefs expected by tests
    "ADMIN_ROLE",
    "USER_ROLE",
    "FLEXT_AUTH_ADMIN",
    "FLEXT_AUTH_USER",
    "FLEXT_AUTH_GUEST",
    "FlextAuthRole",
    "FlextAuthPermissions",
    "FlextAuthUserData",
    "FlextAuthSessionData",
    "FlextAuthTokenData",
    "FlextAuthHeaders",
    "FlextAuthClaims",
    # Helper surface expected in tests
    "flext_auth_quick_start",
    "flext_auth_hash_password",
    "flext_auth_verify_password",
    "flext_auth_generate_jwt",
    "flext_auth_validate_jwt",
    "flext_auth_validate_email",
    "flext_auth_validate_password_strength",
    "flext_auth_decode_jwt",
    "flext_auth_create_secure_session",
    "flext_auth_instant_api",
    "flext_auth_one_liner",
    "flext_auth_complete_workflow",
    "flext_auth_check_token",
    "flext_auth_middleware_factory",
    "flext_auth_merge_configs",
    "flext_auth_filter_user_data",
    "flext_auth_create_user_payload",
    "flext_auth_build_response",
    "flext_auth_rate_limit",
    "flext_auth_extract_token_claims",
    "FlextAuthUser",
    "FlextAuthBatchOperations",
    "flext_auth_batch_operations",
    # Enhanced helpers also in __all__ for public interface
    "flext_auth_create_api_key",
    "flext_auth_validate_api_key",
    "flext_auth_create_auth_context",
    "flext_auth_create_multi_factor_token",
    "flext_auth_create_role_hierarchy",
    "flext_auth_validate_permissions",
    "flext_auth_extract_user_context",
    "flext_auth_create_service_token",
]

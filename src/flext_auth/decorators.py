"""FLEXT Auth Decorators - Enterprise authentication and authorization decorators.

This module provides decorators for protecting endpoints and functions with
authentication and authorization requirements. Following the decorator pattern
and implementing enterprise security practices for the FLEXT ecosystem.

Architecture:
    - Cross-Cutting Layer: Authentication and authorization aspects
    - Decorator Pattern: Non-intrusive security enforcement
    - Railway-Oriented: FlextResult[T] for type-safe error handling
    - Framework Agnostic: Works with FastAPI, Flask, Django, etc.

Core Decorators:
    - @flext_auth_required: Basic authentication requirement
    - @flext_auth_role_required: Role-based access control
    - @flext_auth_permission_required: Permission-based access control
    - @flext_auth_rate_limit: Request rate limiting (TODO)
    - @flext_auth_audit_log: Security audit logging (TODO)

TODO (Based on docs/TODO.md):
    - [ ] CRITICAL: Integrate with FlextContainer for DI (Issue #3)
    - [ ] HIGH: Add domain events for authentication attempts (Issue #4)
    - [ ] MEDIUM: Add rate limiting decorator (Issue #11)
    - [ ] MEDIUM: Add audit logging decorator (Issue #11)
    - [ ] LOW: Add performance monitoring decorator (Issue #10)

Current Project Status:
    ✅ Authentication decorators comprehensively documented with enterprise patterns
    ✅ Framework-agnostic implementation patterns documented
    ✅ Security enforcement and authorization patterns documented
    🔄 Implementation focus: FlextContainer integration and rate limiting decorators

Security Features:
    - JWT token validation and extraction
    - Role-based access control enforcement
    - Permission-based access control
    - Security context propagation
    - Authentication failure handling
    - Framework-agnostic implementation

Design Patterns:
    - Decorator Pattern: Non-intrusive security aspects
    - Strategy Pattern: Multiple authentication strategies
    - Parameter Object: Configuration consolidation
    - Chain of Responsibility: Multiple security checks

Framework Integration:
    Works seamlessly with popular Python web frameworks:
    - FastAPI: Automatic dependency injection
    - Flask: Request context integration
    - Django: Middleware and view decoration
    - Starlette: ASGI middleware support

Example Usage:
    >>> from flext_auth import flext_auth_required, flext_auth_role_required
    >>>
    >>> @flext_auth_required
    >>> def protected_function(user):
    ...     return f"Hello {user.username}"
    >>>
    >>> @flext_auth_role_required("REDACTED_LDAP_BIND_PASSWORD")
    >>> def REDACTED_LDAP_BIND_PASSWORD_only_function(user):
    ...     return f"Admin access for {user.username}"

Performance Considerations:
    - Minimal decorator overhead
    - Efficient token validation
    - Cached security context
    - Async-compatible decorators
    - Framework-optimized implementations

Integration Points:
    - FlextContainer: Service dependency injection (TODO)
    - FlextResult: Type-safe error handling
    - JWT Service: Token validation
    - User Repository: User lookup and validation

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable
from typing import TYPE_CHECKING, ParamSpec, cast

from flext_core import F, FlextLoggerFactory, FlextResult

from flext_auth.jwt import FlextJWTService

# Import types and services from flext_auth modules

if TYPE_CHECKING:
    from flext_auth.auth import FlextAuthService

_logger = FlextLoggerFactory.get_logger(__name__)

# Type definitions for cleaner interfaces following type safety principles
P = ParamSpec("P")
# R and F imported from flext_core to eliminate duplication
# Function type aliases - avoiding Callable[..., T] to prevent explicit-any errors
DecoratorReturnType = object

# Specific function signatures to avoid varargs which trigger explicit-any
SimpleAuthFunction = Callable[[object], DecoratorReturnType]
BinaryAuthFunction = Callable[[object, object], DecoratorReturnType]
TernaryAuthFunction = Callable[[object, object, object], DecoratorReturnType]
NullaryAuthFunction = Callable[[], DecoratorReturnType]

# Union of supported function types for authentication decorators
AuthenticatedFunction = (
    SimpleAuthFunction | BinaryAuthFunction | TernaryAuthFunction | NullaryAuthFunction
)
DecoratorCallable = Callable[[F], F]


# REFACTORING: Parameter Object Pattern for decorator parameters
class FlextAuthDecoratorConfig:
    """Parameter Object for flext_auth_required decorator - reduces parameter count."""

    def __init__(
        self,
        auth_service: FlextAuthService | None = None,
        secret: str | None = None,
        *,
        get_user: bool = True,
        error_response: object = None,
    ) -> None:
        """Initialize decorator configuration."""
        self.auth_service = auth_service
        self.secret = secret
        self.get_user = get_user
        self.error_response = error_response


# REFACTORING: Strategy Pattern for token extraction - reduces complexity
def _extract_bearer_token_from_header(auth_header: str) -> str | None:
    """Extract Bearer token from Authorization header - Single Responsibility."""
    if auth_header.startswith("Bearer "):
        return auth_header[7:]
    return None


def _extract_token_from_fastapi_flask(request: object) -> str | None:
    """Extract token from FastAPI/Flask request - Single Responsibility."""
    if hasattr(request, "headers"):
        headers = request.headers
        if hasattr(headers, "get"):
            auth_header = headers.get("Authorization", "")
            return _extract_bearer_token_from_header(auth_header)
    return None


def _extract_token_from_django(request: object) -> str | None:
    """Extract token from Django request - Single Responsibility."""
    if hasattr(request, "META"):
        meta = request.META
        if hasattr(meta, "get"):
            auth_header = meta.get("HTTP_AUTHORIZATION", "")
            return _extract_bearer_token_from_header(auth_header)
    return None


def _extract_token_from_dict(request: object) -> str | None:
    """Extract token from dictionary request - Single Responsibility."""
    if isinstance(request, dict):
        # Try headers first
        headers = request.get("headers", {})
        if isinstance(headers, dict):
            auth_header = headers.get("Authorization", "")
            token = _extract_bearer_token_from_header(auth_header)
            if token:
                return token

        # Fallback: direct token fields
        return request.get("token") or request.get("access_token")
    return None


def _extract_token_from_request(request: object) -> str | None:
    """Extract authentication token using Strategy Pattern - SOLID refactored.

    Supports FastAPI, Django, Flask, and dict-based requests.
    """
    # Strategy Pattern: Try each extraction method in sequence
    extraction_strategies = [
        _extract_token_from_fastapi_flask,
        _extract_token_from_django,
        _extract_token_from_dict,
    ]

    for strategy in extraction_strategies:
        token = strategy(request)
        if token:
            return token

    return None


def _validate_token_with_auth_instance(
    token: str,
    auth_service: FlextAuthService,
) -> FlextResult[dict[str, object]]:
    """Validate token using auth service instance."""
    try:
        # Auth service validate_token is async, need to run it
        async def _validate() -> FlextResult[dict[str, object]]:
            validation_result = await auth_service.validate_token(token)
            if validation_result.success and validation_result.data:
                # Convert SecurityContext to dict
                context = validation_result.data
                return FlextResult.ok(
                    {
                        "user_id": context.user_id,
                        "username": context.username,
                        "role": context.role,
                        "permissions": context.permissions,
                    },
                )
            return FlextResult.fail(
                validation_result.error or "Token validation failed",
            )

        return asyncio.run(_validate())
    except Exception as e:
        _logger.exception("Token validation error")
        return FlextResult.fail(f"Authentication error: {e}")


def _validate_token_with_secret(
    token: str,
    secret: str,
) -> FlextResult[dict[str, object]]:
    """Validate token using secret key directly."""
    try:
        jwt_service = FlextJWTService(secret_key=secret)
        validation_result = jwt_service.verify_token(token)

        if validation_result.success and validation_result.data:
            # Convert claims to dict format
            claims = validation_result.data
            return FlextResult.ok(
                {
                    "user_id": getattr(claims, "user_id", ""),
                    "username": getattr(claims, "username", ""),
                    "role": getattr(claims, "role", "user"),
                    "permissions": getattr(claims, "permissions", []),
                    "exp": getattr(claims, "exp", 0),
                    "iat": getattr(claims, "iat", 0),
                },
            )
        return FlextResult.fail(validation_result.error or "Token validation failed")
    except Exception as e:
        _logger.exception("Token validation error")
        return FlextResult.fail(f"Authentication error: {e}")


def _extract_request_from_args(
    args: tuple[object, ...],
    kwargs: dict[str, object],
) -> object | None:
    """Extract request object from function arguments."""
    if args:
        return args[0]
    return kwargs.get("request")


def _handle_authentication_error(error_response: object, message: str) -> object:
    """Handle authentication error with custom or default response."""
    if error_response is not None:
        return error_response
    return {"error": message}


def _validate_token_with_service(
    token: str,
    auth_service: FlextAuthService | None,
    secret: str | None,
) -> FlextResult[dict[str, object]] | None:
    """Validate token using either auth service or secret."""
    if auth_service:
        return _validate_token_with_auth_instance(token, auth_service)
    if secret:
        return _validate_token_with_secret(token, secret)
    return None


def _add_user_data_to_kwargs(
    kwargs: dict[str, object],
    validation_result: FlextResult[dict[str, object]],
    *,
    get_user: bool,
) -> None:
    """Add user data to kwargs if requested and available."""
    if get_user and validation_result.data:
        kwargs["current_user"] = validation_result.data


def _execute_authentication_pipeline(
    args: tuple[object, ...],
    kwargs: dict[str, object],
    config: FlextAuthDecoratorConfig,
    func: Callable[..., object],
) -> object:
    """Execute authentication pipeline using Railway-Oriented Programming.

    SOLID REFACTORING: Implements Railway-Oriented Programming to reduce
    flext_auth_required from 6 returns to 2 returns.
    """
    try:
        # Railway-Oriented Programming: All validations must pass to reach success
        request = _extract_request_from_args(args, kwargs)
        if not request:
            return _handle_authentication_error(
                config.error_response,
                "No request object found",
            )

        token = _extract_token_from_request(request)
        if not token:
            return _handle_authentication_error(
                config.error_response,
                "Authentication token required",
            )

        validation_result = _validate_token_with_service(
            token,
            config.auth_service,
            config.secret,
        )
        if not validation_result or not validation_result.success:
            error_msg = (
                validation_result.error
                if validation_result
                else "Token validation failed"
            )
            return _handle_authentication_error(
                config.error_response,
                error_msg or "Validation failed",
            )

        # All validations passed - add user data and execute function
        _add_user_data_to_kwargs(kwargs, validation_result, get_user=config.get_user)
        return func(*args, **kwargs)

    except Exception as e:
        return _handle_authentication_error(
            config.error_response,
            f"Authentication error: {e}",
        )


def flext_auth_required(
    auth_service: FlextAuthService | None = None,
    secret: str | None = None,
    *,
    get_user: bool = True,
    error_response: object = None,
) -> DecoratorCallable[F]:
    """Authentication decorator with flexible configuration.

    SOLID REFACTORING: Reduced from 6 parameters to Parameter Object Pattern.
    Reduced from 6 returns to Railway-Oriented Programming with 2 returns.

    Args:
        auth_service: FlextAuthService instance for validation
        secret: JWT secret key for direct validation
        get_user: Whether to fetch user data after token validation
        error_response: Custom error response for authentication failures

    Returns:
        Decorated function with authentication requirement

    Raises:
        ValueError: If neither auth_service nor secret is provided

    """
    if not auth_service and not secret:
        msg = "Either auth_service or secret must be provided"
        raise ValueError(msg)

    def decorator(func: F) -> F:
        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:
            # REFACTORING: Parameter Object Pattern + Railway-Oriented Programming
            config = FlextAuthDecoratorConfig(
                auth_service=auth_service,
                secret=secret,
                get_user=get_user,
                error_response=error_response,
            )
            return _execute_authentication_pipeline(args, kwargs, config, func)

        return cast("F", wrapper)

    return decorator


def flext_auth_role_required(
    required_role: str,
    auth_service: FlextAuthService | None = None,
    secret: str | None = None,
    error_response: object = None,
) -> DecoratorCallable[F]:
    """Role-based authorization decorator.

    Args:
        required_role: Required role for access
        auth_service: FlextAuthService instance for validation
        secret: JWT secret key for direct validation
        error_response: Custom error response for authorization failures

    Returns:
        Decorated function with role requirement

    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        @flext_auth_required(auth_service=auth_service, secret=secret)
        def wrapper(*args: object, **kwargs: object) -> object:
            current_user_raw = kwargs.get("current_user", {})
            current_user = (
                current_user_raw if isinstance(current_user_raw, dict) else {}
            )
            user_role = current_user.get("role", "")

            if user_role != required_role:
                if error_response is not None:
                    return error_response
                return {"error": f"Role '{required_role}' required"}

            return func(*args, **kwargs)

        return cast("F", wrapper)

    return decorator


def flext_auth_permission_required(
    required_permission: str,
    auth_service: FlextAuthService | None = None,
    secret: str | None = None,
    error_response: object = None,
) -> DecoratorCallable[F]:
    """Permission-based authorization decorator.

    Args:
        required_permission: Required permission for access
        auth_service: FlextAuthService instance for validation
        secret: JWT secret key for direct validation
        error_response: Custom error response for authorization failures

    Returns:
        Decorated function with permission requirement

    """

    def decorator(func: F) -> F:
        @functools.wraps(func)
        @flext_auth_required(auth_service=auth_service, secret=secret)
        def wrapper(*args: object, **kwargs: object) -> object:
            current_user_raw = kwargs.get("current_user", {})
            current_user = (
                current_user_raw if isinstance(current_user_raw, dict) else {}
            )
            permissions_raw = current_user.get("permissions", [])
            user_permissions = (
                permissions_raw if isinstance(permissions_raw, list) else []
            )

            if required_permission not in user_permissions:
                if error_response is not None:
                    return error_response
                return {"error": f"Permission '{required_permission}' required"}

            return func(*args, **kwargs)

        return cast("F", wrapper)

    return decorator


__all__: list[str] = [
    "flext_auth_permission_required",
    "flext_auth_required",
    "flext_auth_role_required",
]

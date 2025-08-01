"""FLEXT Auth Decorators Module.

Authentication and authorization decorators for enterprise applications.
Implements SOLID principles with dependency injection and proper error handling.
"""

from __future__ import annotations

import asyncio
import functools
from collections.abc import Callable
from typing import TYPE_CHECKING, ParamSpec, TypeVar, cast

from flext_core import FlextLoggerFactory, FlextResult

from flext_auth.jwt import FlextJWTService

# Import types and services from flext_auth modules

if TYPE_CHECKING:
    from flext_auth.auth import FlextAuthService

_logger = FlextLoggerFactory.get_logger(__name__)

# Type definitions for cleaner interfaces following type safety principles
P = ParamSpec("P")
R = TypeVar("R")
# Use object instead of Any for strict mypy compatibility
F = TypeVar("F", bound=Callable[..., object])  # type: ignore[explicit-any]
AuthenticatedFunction = Callable[..., object]  # type: ignore[explicit-any]
DecoratorCallable = Callable[[F], F]  # type: ignore[explicit-any]


# SOLID REFACTORING: Strategy Pattern for token extraction - reduces complexity
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
            if validation_result.is_success and validation_result.data:
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

        if validation_result.is_success and validation_result.data:
            # Convert claims to dict format
            claims = validation_result.data
            return FlextResult.ok(
                {
                    "user_id": getattr(claims, "user_id", ""),
                    "username": getattr(claims, "username", ""),
                    "role": getattr(claims, "role", "user"),
                    "exp": getattr(claims, "exp", 0),
                    "iat": getattr(claims, "iat", 0),
                },
            )
        return FlextResult.fail(validation_result.error or "Token validation failed")
    except Exception as e:
        _logger.exception("Token validation error")
        return FlextResult.fail(f"Authentication error: {e}")


def _extract_request_from_args(
    args: tuple[object, ...], kwargs: dict[str, object],
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


def flext_auth_required(  # type: ignore[explicit-any]
    auth_service: FlextAuthService | None = None,
    secret: str | None = None,
    *,
    get_user: bool = True,
    error_response: object = None,
) -> DecoratorCallable[F]:
    """Authentication decorator with flexible configuration.

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

    def decorator(func: F) -> F:  # type: ignore[explicit-any]
        @functools.wraps(func)
        def wrapper(*args: object, **kwargs: object) -> object:  # type: ignore[misc]
            # Extract request from arguments
            request = _extract_request_from_args(args, kwargs)
            if not request:
                return _handle_authentication_error(
                    error_response, "No request object found",
                )

            # Extract and validate token
            token = _extract_token_from_request(request)
            if not token:
                return _handle_authentication_error(
                    error_response, "Authentication token required",
                )

            # Validate token with service
            validation_result = _validate_token_with_service(
                token, auth_service, secret,
            )
            if not validation_result or not validation_result.is_success:
                error_msg = (
                    validation_result.error
                    if validation_result
                    else "Token validation failed"
                )
                return _handle_authentication_error(
                    error_response, error_msg or "Validation failed",
                )

            # Add user data to kwargs if requested
            _add_user_data_to_kwargs(kwargs, validation_result, get_user=get_user)

            return func(*args, **kwargs)

        return cast("F", wrapper)  # type: ignore[explicit-any]

    return decorator


def flext_auth_role_required(  # type: ignore[explicit-any]
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

    def decorator(func: F) -> F:  # type: ignore[explicit-any]
        @functools.wraps(func)
        @flext_auth_required(auth_service=auth_service, secret=secret)  # type: ignore[arg-type]
        def wrapper(*args: object, **kwargs: object) -> object:  # type: ignore[misc]
            current_user = cast("dict[str, object]", kwargs.get("current_user", {}))
            user_role = current_user.get("role", "")

            if user_role != required_role:
                if error_response is not None:
                    return error_response
                return {"error": f"Role '{required_role}' required"}

            return func(*args, **kwargs)

        return cast("F", wrapper)  # type: ignore[explicit-any]

    return decorator


def flext_auth_permission_required(  # type: ignore[explicit-any]
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

    def decorator(func: F) -> F:  # type: ignore[explicit-any]
        @functools.wraps(func)
        @flext_auth_required(auth_service=auth_service, secret=secret)  # type: ignore[arg-type]
        def wrapper(*args: object, **kwargs: object) -> object:  # type: ignore[misc]
            current_user = cast("dict[str, object]", kwargs.get("current_user", {}))
            user_permissions = cast("list[str]", current_user.get("permissions", []))

            if required_permission not in user_permissions:
                if error_response is not None:
                    return error_response
                return {"error": f"Permission '{required_permission}' required"}

            return func(*args, **kwargs)

        return cast("F", wrapper)  # type: ignore[explicit-any]

    return decorator


__all__ = [
    "flext_auth_permission_required",
    "flext_auth_required",
    "flext_auth_role_required",
]

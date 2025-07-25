"""FastAPI dependencies for authentication."""

from __future__ import annotations

from typing import Annotated

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from flext_auth.api.middleware import AuthMiddleware, RateLimitMiddleware
from flext_auth.domain.value_objects import SecurityContext
from flext_auth.services.auth_service import AuthService

# Global instances - would be properly configured in production
_auth_service: AuthService | None = None
_auth_middleware: AuthMiddleware | None = None
_rate_limiter: RateLimitMiddleware | None = None


def configure_dependencies(auth_service: AuthService) -> None:
    """Configure global dependencies."""
    global _auth_service, _auth_middleware, _rate_limiter  # noqa: PLW0603
    _auth_service = auth_service
    _auth_middleware = AuthMiddleware(auth_service)
    _rate_limiter = RateLimitMiddleware()


def get_auth_service() -> AuthService:
    """Get auth service dependency."""
    if _auth_service is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication service not configured",
        )
    return _auth_service


def get_auth_middleware() -> AuthMiddleware:
    """Get auth middleware dependency."""
    if _auth_middleware is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Authentication middleware not configured",
        )
    return _auth_middleware


def get_rate_limiter() -> RateLimitMiddleware:
    """Get rate limiter dependency."""
    if _rate_limiter is None:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Rate limiter not configured",
        )
    return _rate_limiter


async def get_current_user(
    request: Request,
    credentials: Annotated[
        HTTPAuthorizationCredentials | None,
        Depends(HTTPBearer(auto_error=False)),
    ],
    auth_middleware: Annotated[AuthMiddleware, Depends(get_auth_middleware)],
) -> SecurityContext:
    """Get current authenticated user dependency."""
    return await auth_middleware.get_current_user(request, credentials)


async def get_current_active_user(
    current_user: Annotated[SecurityContext, Depends(get_current_user)],
) -> SecurityContext:
    """Get current active user dependency."""
    # Additional checks could be added here
    return current_user


async def check_rate_limit(
    request: Request,
    rate_limiter: Annotated[RateLimitMiddleware, Depends(get_rate_limiter)],
) -> None:
    """Check rate limit dependency."""
    await rate_limiter.check_rate_limit(request)


def require_REDACTED_LDAP_BIND_PASSWORD(
    current_user: Annotated[SecurityContext, Depends(get_current_active_user)],
) -> SecurityContext:
    """Require REDACTED_LDAP_BIND_PASSWORD role dependency."""
    if current_user.role != "REDACTED_LDAP_BIND_PASSWORD":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin access required",
        )
    return current_user


def get_client_ip(request: Request) -> str:
    """Get client IP address."""
    # Check for forwarded headers first
    forwarded_for = request.headers.get("X-Forwarded-For")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()

    real_ip = request.headers.get("X-Real-IP")
    if real_ip:
        return real_ip.strip()

    # Fallback to client host
    return getattr(request.client, "host", "unknown")


def get_user_agent(request: Request) -> str | None:
    """Get user agent from request."""
    return request.headers.get("User-Agent")


# Type aliases for common dependencies
AuthServiceDep = Annotated[AuthService, Depends(get_auth_service)]
CurrentUser = Annotated[SecurityContext, Depends(get_current_user)]
ActiveUser = Annotated[SecurityContext, Depends(get_current_active_user)]
AdminUser = Annotated[SecurityContext, Depends(require_REDACTED_LDAP_BIND_PASSWORD)]
ClientIP = Annotated[str, Depends(get_client_ip)]
UserAgent = Annotated[str | None, Depends(get_user_agent)]
RateLimit = Depends(check_rate_limit)

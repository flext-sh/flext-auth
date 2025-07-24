"""Authentication middleware for FastAPI."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from fastapi import HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_auth.domain.value_objects import SecurityContext
    from flext_auth.services.auth_service import AuthService


class AuthMiddleware:
    """Authentication middleware for protecting routes."""

    def __init__(self, auth_service: AuthService) -> None:
        """Initialize middleware with auth service."""
        self.auth_service = auth_service
        self.security = HTTPBearer(auto_error=False)

    async def get_current_user(
        self, request: Request, credentials: HTTPAuthorizationCredentials | None = None
    ) -> SecurityContext:
        """Get current authenticated user from token."""
        if not credentials:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication required",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Validate token
        token_result = await self.auth_service.validate_token(credentials.credentials)
        if not token_result.is_success:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {token_result.error}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        return token_result.data


class RateLimitMiddleware:
    """Rate limiting middleware."""

    def __init__(
        self,
        requests_per_minute: int = 60,
        requests_per_hour: int = 1000,
    ) -> None:
        """Initialize rate limiter."""
        self.requests_per_minute = requests_per_minute
        self.requests_per_hour = requests_per_hour
        self._minute_requests: dict[str, list[float]] = {}
        self._hour_requests: dict[str, list[float]] = {}

    def _get_client_id(self, request: Request) -> str:
        """Get client identifier for rate limiting."""
        # Use X-Forwarded-For header if available, otherwise use client IP
        forwarded_for = request.headers.get("X-Forwarded-For")
        if forwarded_for:
            return forwarded_for.split(",")[0].strip()

        return getattr(request.client, "host", "unknown")

    def _cleanup_old_requests(self, requests: list[float], window_seconds: int) -> None:
        """Remove requests outside the time window."""
        current_time = time.time()
        cutoff_time = current_time - window_seconds

        # Remove old requests
        while requests and requests[0] < cutoff_time:
            requests.pop(0)

    async def check_rate_limit(self, request: Request) -> None:
        """Check if request exceeds rate limits."""
        client_id = self._get_client_id(request)
        current_time = time.time()

        # Initialize client request lists if not exists
        if client_id not in self._minute_requests:
            self._minute_requests[client_id] = []
        if client_id not in self._hour_requests:
            self._hour_requests[client_id] = []

        minute_requests = self._minute_requests[client_id]
        hour_requests = self._hour_requests[client_id]

        # Clean up old requests
        self._cleanup_old_requests(minute_requests, 60)  # 1 minute
        self._cleanup_old_requests(hour_requests, 3600)  # 1 hour

        # Check limits
        if len(minute_requests) >= self.requests_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded: too many requests per minute",
                headers={"Retry-After": "60"},
            )

        if len(hour_requests) >= self.requests_per_hour:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded: too many requests per hour",
                headers={"Retry-After": "3600"},
            )

        # Add current request
        minute_requests.append(current_time)
        hour_requests.append(current_time)


class SecurityHeadersMiddleware:
    """Security headers middleware."""

    def __init__(self) -> None:
        """Initialize security headers."""
        self.security_headers = {
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Content-Security-Policy": "default-src 'self'",
        }

    async def add_security_headers(self, request: Request, call_next: Callable) -> None:
        """Add security headers to response."""
        response = await call_next(request)

        for header, value in self.security_headers.items():
            response.headers[header] = value

        return response

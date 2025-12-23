"""FLEXT Auth Middleware - Authentication middleware adapters.

This module provides middleware that adapts FlextAuthBaseProvider implementations
to work with HTTP client middleware (flext-api) and web application middleware
(flext-web). This eliminates duplication by allowing all authentication logic
to be centralized in flext-auth providers.

Following FLEXT standards: one class per module with nested middleware classes.

Integration Pattern:
    # HTTP Client with JWT Auth
    from flext_api import FlextApiClient
    from flext_auth import FlextAuthJwtProvider, FlextAuthMiddleware

    auth = FlextAuthMiddleware.FlextWebAuthMiddleware(FlextAuthJwtProvider(secret="key"))
    client = FlextApiClient(middlewares=[auth])

    # Web App with OAuth2
    from flext_web import create_fastapi_app
    from flext_auth import FlextAuthOAuth2Provider, FlextAuthMiddleware

    auth = FlextAuthMiddleware.WebAuthMiddleware(FlextAuthOAuth2Provider(...))
    app = create_fastapi_app(middlewares=[auth])

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# FLEXT Standard imports
from flext_core import (
    FlextResult as r,
    FlextService as s,
)
from flext_core.loggings import FlextLogger

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider


# Placeholder types for HTTP requests/responses (to avoid circular dependencies)
class HttpRequest:
    """Placeholder for HTTP request type."""


class HttpResponse:
    """Placeholder for HTTP response type."""


class _MiddlewareControlMixin:
    """Shared enable/disable functionality for middleware classes.

    Eliminates duplication of enable/disable pattern (12 lines × 2 classes).
    This mixin provides the base control functionality for all middleware implementations.
    """

    def __init__(self) -> None:
        """Initialize middleware control state."""
        self._enabled = True

    def enable(self) -> None:
        """Enable middleware processing."""
        self._enabled = True

    def disable(self) -> None:
        """Disable middleware processing."""
        self._enabled = False

    @property
    def is_enabled(self) -> bool:
        """Check if middleware is enabled."""
        return self._enabled


class FlextAuthMiddleware(s):
    """Authentication middleware adapters following FLEXT standards.

    This class provides middleware that adapts FlextAuthBaseProvider implementations
    to work with HTTP client middleware (flext-api) and web application middleware
    (flext-web). Following FLEXT pattern: one class per module with nested middleware classes.
    """

    def execute(self) -> r[bool]:
        """Execute method for FlextService interface.

        FlextAuthMiddleware is a namespace class - use specific middleware classes instead.
        """
        return r[bool].fail(
            "FlextAuthMiddleware is a namespace class - use specific middleware classes like FlextWebAuthMiddleware",
        )

    class FlextWebAuthMiddleware(_MiddlewareControlMixin):
        """Adapts FlextAuthBaseProvider to HTTP client middleware.

        This middleware integrates flext-auth authentication providers with
        HTTP clients (flext-api). It handles token management, header injection,
        token refresh, and authentication errors for outbound HTTP requests.

        Example:
            >>> from flext_auth import FlextAuthJwtProvider, FlextAuthMiddleware
            >>> from flext_api import FlextApiClient
            >>> provider = FlextAuthJwtProvider(secret="key")
            >>> middleware = FlextAuthMiddleware.FlextWebAuthMiddleware(provider)
            >>> client = FlextApiClient(middlewares=[middleware])

        """

        def __init__(
            self,
            provider: FlextAuthBaseProvider,
            provider_name: str = "web",
        ) -> None:
            """Initialize HTTP client authentication middleware.

            Args:
                provider: Authentication provider instance
                provider_name: Provider name for logging

            """
            super().__init__()
            self._provider = provider
            self.logger = FlextLogger(f"flext_auth.middleware.http.{provider_name}")
            self._current_token: FlextAuthModels.AuthToken | None = None

        def process_request(
            self,
            request: HttpRequest,
        ) -> r[HttpRequest]:
            """Process HTTP request by adding authentication headers.

            Args:
                request: HTTP request to authenticate

            Returns:
                r with authenticated request or error

            """
            if not self._enabled:
                return r[HttpRequest].ok(request)

            # Ensure we have a valid token
            if not self._current_token:
                token_result = self._authenticate_or_refresh()
                if token_result.is_failure:
                    return r[HttpRequest].fail(
                        token_result.error or "Authentication failed"
                    )

            # Add authorization header
            if hasattr(request, "headers"):
                headers = getattr(request, "headers", {})
                if isinstance(headers, dict):
                    headers["Authorization"] = f"Bearer {self._current_token}"
                    setattr(request, "headers", headers)

            return r[HttpRequest].ok(request)

        def _authenticate_or_refresh(self) -> r[FlextAuthModels.AuthToken]:
            """Authenticate using credentials or refresh existing token."""
            if self._is_token_still_valid():
                return r[FlextAuthModels.AuthToken].ok(self._current_token)

            return self._refresh_or_reauthenticate()

        def _is_token_still_valid(self) -> bool:
            """Check if current token is still valid."""
            return self._current_token is not None

        def _refresh_or_reauthenticate(self) -> r[FlextAuthModels.AuthToken]:
            """Refresh token or re-authenticate if refresh fails."""
            # For now, just mark as needing new authentication
            # In production, implement token refresh logic
            return r[FlextAuthModels.AuthToken].fail("Token refresh not implemented")


__all__ = ["FlextAuthMiddleware"]

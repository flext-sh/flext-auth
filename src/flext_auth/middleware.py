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

from typing import override

from flext_auth.models import m
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.typings import t
from flext_auth.utilities import u
from flext_core import FlextLogger, r, s


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


class FlextAuthMiddleware(s[bool]):
    """Authentication middleware adapters following FLEXT standards.

    This class provides middleware that adapts FlextAuthBaseProvider implementations
    to work with HTTP client middleware (flext-api) and web application middleware
    (flext-web). Following FLEXT pattern: one class per module with nested middleware classes.
    """

    @override
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
            self._current_token: m.Auth.AuthToken | None = None

        def process_request(
            self,
            request: t.GeneralValueType,
        ) -> r[t.GeneralValueType]:
            """Process HTTP request by adding authentication headers.

            Args:
                request: HTTP request to authenticate

            Returns:
                r with authenticated request or error

            """
            if not self._enabled:
                return r[t.GeneralValueType].ok(request)

            if not self._is_token_still_valid():
                token_result = self._authenticate_or_refresh()
                if token_result.is_failure:
                    return r[t.GeneralValueType].fail(
                        token_result.error or "Authentication failed",
                    )
                self._current_token = token_result.value

            if self._current_token is None:
                return r[t.GeneralValueType].fail("Authentication token is not available")

            # Add authorization header (if headers is writable)
            try:
                headers = request.headers if hasattr(request, "headers") else {}
                if u.is_dict_like(headers):
                    mutable_headers = dict(headers)
                    mutable_headers["Authorization"] = (
                        f"Bearer {self._current_token.token}"
                    )
                    setattr(request, "headers", mutable_headers)
            except (AttributeError, TypeError):
                # Headers might be read-only, skip if not writable
                pass

            return r[t.GeneralValueType].ok(request)

        def _authenticate_or_refresh(self) -> r[m.Auth.AuthToken]:
            """Authenticate using credentials or refresh existing token."""
            if self._is_token_still_valid() and self._current_token is not None:
                return r[m.Auth.AuthToken].ok(self._current_token)

            return self._refresh_or_reauthenticate()

        def _is_token_still_valid(self) -> bool:
            """Check if current token is still valid."""
            token = self._current_token
            if token is None:
                return False

            if token.is_expired or token.is_revoked:
                return False

            validation_result = self._provider.validate(token.token)
            if validation_result.is_failure:
                return False

            return validation_result.value

        def _refresh_or_reauthenticate(self) -> r[m.Auth.AuthToken]:
            """Refresh token or re-authenticate if refresh fails."""
            current_token = self._current_token
            if current_token is None:
                return r[m.Auth.AuthToken].fail(
                    "No token available for refresh",
                )

            refresh_input = current_token.refresh_token or current_token.token
            if not refresh_input:
                return r[m.Auth.AuthToken].fail(
                    "No refresh token available",
                )

            validation_result = self._provider.validate(refresh_input)
            if validation_result.is_failure:
                return r[m.Auth.AuthToken].fail(
                    validation_result.error or "Refresh source token is invalid",
                )
            if not validation_result.value:
                return r[m.Auth.AuthToken].fail(
                    "Refresh source token is invalid",
                )

            refresh_result = self._provider.refresh(refresh_input)
            if refresh_result.is_failure:
                return r[m.Auth.AuthToken].fail(
                    refresh_result.error or "Token refresh failed",
                )

            refreshed_payload = refresh_result.value
            identity_id_value = (
                refreshed_payload.identity_id
                if hasattr(refreshed_payload, "identity_id")
                else ""
            )
            if not isinstance(identity_id_value, str) or not identity_id_value:
                user_id_value = (
                    refreshed_payload.user_id
                    if hasattr(refreshed_payload, "user_id")
                    else ""
                )
                if isinstance(user_id_value, str) and user_id_value:
                    identity_id_value = user_id_value
                else:
                    identity_id_value = current_token.identity_id

            try:
                refreshed_token = m.Auth.AuthToken(
                    identity_id=identity_id_value,
                    token=refreshed_payload.token,
                    token_type=refreshed_payload.token_type
                    if hasattr(refreshed_payload, "token_type")
                    else "Bearer",
                    expires_at=refreshed_payload.expires_at,
                    is_revoked=bool(
                        refreshed_payload.is_revoked
                        if hasattr(refreshed_payload, "is_revoked")
                        else False
                    ),
                    refresh_token=refreshed_payload.refresh_token
                    if hasattr(refreshed_payload, "refresh_token")
                    else "",
                )
            except (AttributeError, TypeError, ValueError):
                return r[m.Auth.AuthToken].fail(
                    "Provider refresh returned invalid token payload",
                )

            self._current_token = refreshed_token
            return r[m.Auth.AuthToken].ok(refreshed_token)


__all__ = ["FlextAuthMiddleware"]

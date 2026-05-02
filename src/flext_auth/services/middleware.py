"""FLEXT Auth Middleware - Authentication middleware adapters.

This module provides middleware that adapts p.Auth.FlextAuthBaseProvider implementations
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

    # flext-web bootstrap through its public facade
    from flext_web import web

    app_result = web.create_fastapi_app()
    if app_result.success:
        app = app_result.value

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_api import r

from flext_auth import c, m, p, t
from flext_auth.base import s
from flext_core import u


class FlextAuthMiddleware(s):
    """Authentication middleware adapters following FLEXT standards.

    This class provides middleware that adapts p.Auth.FlextAuthBaseProvider implementations
    to work with HTTP client middleware (flext-api) and web application middleware
    (flext-web). Following FLEXT pattern: one class per module with nested middleware classes.
    """

    class _MiddlewareControlMixin:
        """Shared enable/disable functionality for middleware classes."""

        def __init__(self) -> None:
            """Initialize middleware control state."""
            self._enabled = True

        @property
        def is_enabled(self) -> bool:
            """Check if middleware is enabled."""
            return self._enabled

        def disable(self) -> None:
            """Disable middleware processing."""
            self._enabled = False

        def enable(self) -> None:
            """Enable middleware processing."""
            self._enabled = True

    @override
    def execute(self) -> p.Result[p.Base]:
        """Execute method for s interface.

        FlextAuthMiddleware is a namespace class - use specific middleware classes instead.
        """
        return r[p.Base].fail(
            "FlextAuthMiddleware is a namespace class - use specific middleware classes like FlextWebAuthMiddleware",
        )

    class FlextWebAuthMiddleware(_MiddlewareControlMixin):
        """Adapts p.Auth.FlextAuthBaseProvider to HTTP client middleware.

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
            provider: p.Auth.FlextAuthBaseProvider,
            provider_name: str = "web",
        ) -> None:
            """Initialize HTTP client authentication middleware.

            Args:
                provider: Authentication provider instance
                provider_name: Provider name for logging

            """
            super().__init__()
            self._provider = provider
            self.logger = u.fetch_logger(f"flext_auth.middleware.http.{provider_name}")
            self._current_token: m.Auth.AuthToken | None = None

        def process_request(
            self,
            request: p.Auth.RequestWithHeaders,
        ) -> p.Result[p.Auth.RequestWithHeaders]:
            """Process HTTP request by adding authentication headers.

            Args:
                request: HTTP request with headers to authenticate

            Returns:
                r with authenticated request or error

            """
            if not self._enabled:
                return r[p.Auth.RequestWithHeaders].ok(request)
            if not self._is_token_still_valid():
                token_result = self._authenticate_or_refresh()
                if token_result.failure:
                    return r[p.Auth.RequestWithHeaders].fail(
                        token_result.error or "Authentication failed",
                    )
                self._current_token = token_result.value
            if self._current_token is None:
                return r[p.Auth.RequestWithHeaders].fail(
                    "Authentication token is not available",
                )
            try:
                headers_val = request.headers
                mutable_headers: t.MutableStrMapping = dict(headers_val.items())
                mutable_headers["Authorization"] = f"Bearer {self._current_token.token}"
                request.headers = mutable_headers
            except c.EXC_ATTR_TYPE as exc:
                return r[p.Auth.RequestWithHeaders].fail(
                    f"Unable to attach authorization header: {exc}",
                )
            return r[p.Auth.RequestWithHeaders].ok(request)

        def _authenticate_or_refresh(self) -> p.Result[m.Auth.AuthToken]:
            """Authenticate using credentials or refresh existing token."""
            if self._is_token_still_valid() and self._current_token is not None:
                return r[m.Auth.AuthToken].ok(self._current_token)
            return self._refresh_or_reauthenticate()

        def _is_token_still_valid(self) -> bool:
            """Check if current token is still valid."""
            token = self._current_token
            if token is None:
                return False
            if token.expired or token.is_revoked:
                return False
            validation_result = self._provider.validate(token.token)
            folded: bool = validation_result.fold(
                on_failure=lambda _: False,
                on_success=lambda v: v,
            )
            return folded

        def _refresh_or_reauthenticate(self) -> p.Result[m.Auth.AuthToken]:
            """Refresh token or re-authenticate if refresh fails."""
            current_token = self._current_token
            if current_token is None:
                return r[m.Auth.AuthToken].fail("No token available for refresh")
            refresh_input = current_token.refresh_token or current_token.token
            if not refresh_input:
                return r[m.Auth.AuthToken].fail("No refresh token available")
            validation_result = self._provider.validate(refresh_input)
            if validation_result.failure:
                return r[m.Auth.AuthToken].fail(
                    validation_result.error or "Refresh source token is invalid",
                )
            if not validation_result.value:
                return r[m.Auth.AuthToken].fail("Refresh source token is invalid")
            refresh_result = self._provider.refresh(refresh_input)
            if refresh_result.failure:
                return r[m.Auth.AuthToken].fail(
                    refresh_result.error or "Token refresh failed",
                )
            refreshed_payload = refresh_result.value
            identity_id_value = (
                refreshed_payload.identity_id
                or refreshed_payload.user_id
                or current_token.identity_id
            )
            try:
                refreshed_token = m.Auth.AuthToken(
                    identity_id=identity_id_value,
                    token=refreshed_payload.token,
                    token_type=refreshed_payload.token_type,
                    expires_at=refreshed_payload.expires_at,
                    is_revoked=refreshed_payload.is_revoked,
                    refresh_token=refreshed_payload.refresh_token,
                )
            except c.EXC_TYPE_VALIDATION:
                return r[m.Auth.AuthToken].fail(
                    "Provider refresh returned invalid token payload",
                )
            self._current_token = refreshed_token
            return r[m.Auth.AuthToken].ok(refreshed_token)


__all__: t.MutableSequenceOf[str] = ["FlextAuthMiddleware"]

"""FLEXT Auth Middleware - Authentication middleware adapters following FLEXT standards.

This module provides middleware that adapts FlextAuthBaseProvider implementations
to work with HTTP client middleware (flext-api) and web application middleware
(flext-web). This eliminates duplication by allowing all authentication logic
to be centralized in flext-auth providers.

Following FLEXT standards: one class per module with nested middleware classes.
Extends flext-core patterns for proper integration.

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

from flext_core import FlextLogger, FlextResult, FlextService

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider


# Placeholder types for HTTP requests/responses (to avoid circular dependencies)
class HttpRequest:
    """Placeholder for HTTP request type."""


class HttpResponse:
    """Placeholder for HTTP response type."""


class _MiddlewareControlMixin:
    """Shared enable/disable functionality for middleware classes.

    Eliminates duplication of enable/disable/is_enabled pattern (12 lines × 2 classes).
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


class FlextAuthMiddleware(FlextService):
    """Authentication middleware adapters following FLEXT standards.

    This class provides middleware that adapts FlextAuthBaseProvider implementations
    to work with HTTP client middleware (flext-api) and web application middleware
    (flext-web). Following FLEXT pattern: one class per module with nested middleware classes.
    """

    def execute(self) -> FlextResult[bool]:
        """Execute method for FlextService interface.

        FlextAuthMiddleware is a namespace class - use specific middleware classes instead.
        """
        return FlextResult[bool].fail(
            "FlextAuthMiddleware is a namespace class - use specific middleware classes like FlextWebAuthMiddleware"
        )

    class FlextWebAuthMiddleware(_MiddlewareControlMixin):
        """Adapts FlextAuthBaseProvider to HTTP client middleware.

        This middleware integrates flext-auth authentication providers with
        HTTP clients (flext-api). It handles token management, header injection,
        token refresh, and authentication errors for outbound HTTP requests.

        Features:
        - Automatic token injection into request headers
        - Token refresh on expiration
        - Credential-based authentication for first request
        - Works with ALL flext-auth providers (JWT, OAuth2, OIDC, SAML, etc.)

        Example:
            >>> from flext_auth import FlextAuthJwtProvider, FlextAuthMiddleware
            >>> from flext_api import FlextApiClient
            >>>
            >>> # Create auth provider
            >>> provider = FlextAuthJwtProvider(secret="my-secret", algorithm="HS256")
            >>>
            >>> # Create middleware that adapts provider
            >>> middleware = FlextAuthMiddleware.FlextWebAuthMiddleware(
            ...     provider=provider,
            ...     credentials={"username": "user", "password": "pass"},
            ...     header_name="Authorization",
            ...     token_prefix="Bearer",
            ... )
            >>>
            >>> # Use with HTTP client
            >>> client = FlextApiClient(middlewares=[middleware])

        """

        def __init__(
            self,
            provider: FlextAuthBaseProvider,
            credentials: dict[str, object] | None = None,
            header_name: str = "Authorization",
            token_prefix: str = "Bearer",
            auto_refresh: bool = True,
        ) -> None:
            """Initialize HTTP authentication middleware.

            Args:
                provider: Authentication provider (any FlextAuthBaseProvider implementation)
                credentials: Initial credentials for authentication (optional)
                header_name: HTTP header name for token (default: "Authorization")
                token_prefix: Token prefix (default: "Bearer", set to "" for no prefix)
                auto_refresh: Automatically refresh expired tokens (default: True)

            """
            super().__init__()  # Initialize mixin
            provider_name = provider.get_metadata()["name"]
            self.name = f"FlextWebAuthMiddleware({provider_name})"
            self._provider = provider
            self._provider_name = provider_name  # Cache provider name
            self._credentials = credentials
            self._header_name = header_name
            self._token_prefix = token_prefix
            self._auto_refresh = auto_refresh
            self.logger = FlextLogger(f"flext_auth.middleware.http.{provider_name}")
            self._current_token: FlextAuthModels.AuthToken | None = None

        def process_request(
            self,
            request: HttpRequest,
        ) -> FlextResult[object]:
            """Process HTTP request by adding authentication headers.

            This method is called by the HTTP client before sending a request.
            It ensures the request has valid authentication by:
            1. Checking if we have a current token
            2. Authenticating if no token exists (using credentials)
            3. Refreshing token if expired (if auto_refresh enabled)
            4. Injecting token into request headers

            Args:
            request: HTTP request to authenticate

            Returns:
            FlextResult with authenticated request or error

            """
            if not self._enabled:
                return FlextResult[object].ok(request)

            try:
                # Ensure we have a valid token
                token_result = self._ensure_valid_token()
                if token_result.is_failure:
                    return FlextResult[object].fail(
                        f"Authentication failed: {token_result.error}"
                    )

                token = token_result.unwrap()

                # Build authorization header value
                # AuthToken model uses 'token' attribute, not 'access_token'
                if self._token_prefix:
                    auth_value = f"{self._token_prefix} {token.token}"
                else:
                    auth_value = token.token

                # Add authentication header to request
                # Use object.__setattr__ to bypass Pydantic's extra="forbid"
                current_headers = (
                    dict[str, object](request.headers)
                    if hasattr(request, "headers")
                    else {}
                )
                current_headers[self._header_name] = auth_value

                object.__setattr__(request, "headers", current_headers)

                # Add user context for tracking
                user_context = {
                    "provider": self._provider.get_metadata()["name"],
                    "token_type": token.token_type,
                }
                object.__setattr__(request, "user_context", user_context)

                self.logger.debug(
                    "Added authentication to HTTP request",
                    header=self._header_name,
                    provider=self._provider.get_metadata()["name"],
                )

                return FlextResult[object].ok(request)

            except Exception as e:
                self.logger.exception(
                    "HTTP authentication middleware failed",
                    error=str(e),
                    provider=self._provider.get_metadata()["name"],
                )
                return FlextResult[object].fail(f"HTTP authentication failed: {e}")

        def process_response(
            self,
            response: HttpResponse,
        ) -> FlextResult[object]:
            """Process HTTP response (pass-through for HTTP auth).

            HTTP auth middleware doesn't need to process responses,
            but this method is required by the middleware protocol.

            Args:
            response: HTTP response

            Returns:
            FlextResult with unchanged response

            """
            return FlextResult[object].ok(response)

        def _ensure_valid_token(self) -> FlextResult[FlextAuthModels.AuthToken]:
            """Ensure we have a valid authentication token (Orchestrator pattern).

            Delegates token lifecycle to specific methods with SRP.
            """
            if not self._current_token:
                return self._authenticate_initial()

            if self._is_token_still_valid():
                return FlextResult[FlextAuthModels.AuthToken].ok(self._current_token)

            return self._refresh_or_reauthenticate()

        def _authenticate_initial(self) -> FlextResult[FlextAuthModels.AuthToken]:
            """Authenticate using credentials for initial token (SRP: Initial auth only)."""
            if not self._credentials:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    "No authentication token and no credentials provided"
                )

            auth_result = self._provider.authenticate(self._credentials)
            if auth_result.is_failure:
                return auth_result

            self._current_token = auth_result.unwrap()
            self.logger.info(
                "Initial authentication successful", provider=self._provider_name
            )
            return FlextResult[FlextAuthModels.AuthToken].ok(self._current_token)

        def _is_token_still_valid(self) -> bool:
            """Check if current token is still valid (SRP: Validation check only)."""
            if not self._current_token:
                return False
            validation_result = self._provider.validate(self._current_token)
            return validation_result.is_success and validation_result.unwrap()

        def _refresh_or_reauthenticate(
            self,
        ) -> FlextResult[FlextAuthModels.AuthToken]:
            """Attempt to refresh or re-authenticate (SRP: Recovery logic only)."""
            # Try to refresh if supported
            if (
                self._auto_refresh
                and "refresh" in self._provider.supports()
                and self._current_token
            ):
                self.logger.debug(
                    "Token expired, attempting refresh", provider=self._provider_name
                )

                refresh_result = self._provider.refresh(self._current_token)
                if refresh_result.is_success:
                    self._current_token = refresh_result.unwrap()
                    self.logger.info(
                        "Token refresh successful", provider=self._provider_name
                    )
                    return FlextResult[FlextAuthModels.AuthToken].ok(
                        self._current_token
                    )

            # Refresh failed or not supported - re-authenticate
            if self._credentials:
                self.logger.debug(
                    "Token refresh failed, re-authenticating",
                    provider=self._provider_name,
                )

                auth_result = self._provider.authenticate(self._credentials)
                if auth_result.is_success:
                    self._current_token = auth_result.unwrap()
                    return FlextResult[FlextAuthModels.AuthToken].ok(
                        self._current_token
                    )

            return FlextResult[FlextAuthModels.AuthToken].fail(
                "Token expired and unable to refresh or re-authenticate"
            )

    class WebAuthMiddleware(_MiddlewareControlMixin):
        """Adapts FlextAuthBaseProvider to web application middleware.

        This middleware integrates flext-auth authentication providers with
        web applications (flext-web FastAPI/Flask). It handles token validation,
        user context extraction, and authentication errors for inbound web requests.

        Features:
        - Automatic token extraction from request headers/cookies
        - Token validation using provider
        - User context injection into request
        - Works with ALL flext-auth providers (JWT, OAuth2, OIDC, SAML, etc.)

        Example:
            >>> from flext_auth import FlextAuthOAuth2Provider, WebAuthMiddleware
            >>> from flext_web import create_fastapi_app
            >>>
            >>> # Create auth provider
            >>> provider = FlextAuthOAuth2Provider(
            ...     client_id="client-id",
            ...     client_secret="secret",
            ...     authorization_url="https://oauth.example.com/auth",
            ... )
            >>>
            >>> # Create middleware that adapts provider
            >>> middleware = WebAuthMiddleware(
            ...     provider=provider,
            ...     header_name="Authorization",
            ...     token_prefix="Bearer",
            ...     exclude_paths=["/health", "/docs"],
            ... )
            >>>
            >>> # Use with web app
            >>> app = create_fastapi_app(middlewares=[middleware])

        """

        def __init__(
            self,
            provider: FlextAuthBaseProvider,
            header_name: str = "Authorization",
            token_prefix: str = "Bearer",
            cookie_name: str | None = None,
            exclude_paths: list[str] | None = None,
            require_auth: bool = True,
        ) -> None:
            """Initialize web authentication middleware.

            Args:
                provider: Authentication provider (any FlextAuthBaseProvider implementation)
                header_name: HTTP header name for token (default: "Authorization")
                token_prefix: Token prefix (default: "Bearer", set to "" for no prefix)
                cookie_name: Cookie name for token (optional, checked after header)
                exclude_paths: Paths that don't require authentication (e.g., ["/health"])
                require_auth: Require authentication for all non-excluded paths (default: True)

            """
            super().__init__()  # Initialize mixin
            provider_name = provider.get_metadata()["name"]
            self.name = f"WebAuthMiddleware({provider_name})"
            self._provider = provider
            self._provider_name = provider_name  # Cache provider name
            self._header_name = header_name
            self._token_prefix = token_prefix
            self._cookie_name = cookie_name
            self._exclude_paths = exclude_paths if exclude_paths is not None else []
            self._require_auth = require_auth
            self.logger = FlextLogger(f"flext_auth.middleware.web.{provider_name}")

        def process_request(
            self,
            request: object,  # FlextWebModels.WebRequest - avoid import
        ) -> FlextResult[object]:
            """Process web request by validating authentication.

            This method is called by the web application for each incoming request.
            It validates authentication by:
            1. Checking if path is excluded (skip auth)
            2. Extracting token from header or cookie
            3. Validating token using provider
            4. Extracting user context and injecting into request

            Args:
            request: Web request to authenticate

            Returns:
            FlextResult with authenticated request (with user context) or error

            """
            if not self._enabled:
                return FlextResult[object].ok(request)

            try:
                # Check if path is excluded from authentication
                request_path = getattr(request, "path", getattr(request, "url", ""))
                if any(
                    request_path.startswith(excluded)
                    for excluded in self._exclude_paths
                ):
                    self.logger.debug(
                        "Request path excluded from authentication",
                        path=request_path,
                    )
                    return FlextResult[object].ok(request)

                # Extract token from request
                token = self._extract_token(request)
                if not token:
                    if self._require_auth:
                        return FlextResult[object].fail(
                            f"Authentication required: No token found in {self._header_name} header or cookies"
                        )
                    return FlextResult[object].ok(request)

                # Validate token
                validation_result = self._provider.validate(token)
                if validation_result.is_failure:
                    return FlextResult[object].fail(
                        f"Token validation failed: {validation_result.error}"
                    )

                if not validation_result.unwrap():
                    return FlextResult[object].fail(
                        "Authentication failed: Invalid or expired token"
                    )

                # Token is valid - add user context to request
                # Note: Actual user context extraction would require provider-specific logic
                # For now, we just mark the request as authenticated
                user_context = {
                    "authenticated": True,
                    "provider": self._provider.get_metadata()["name"],
                    "token": token,
                }

                object.__setattr__(request, "user_context", user_context)

                self.logger.debug(
                    "Web request authenticated",
                    provider=self._provider.get_metadata()["name"],
                    path=request_path,
                )

                return FlextResult[object].ok(request)

            except Exception as e:
                self.logger.exception(
                    "Web authentication middleware failed",
                    error=str(e),
                    provider=self._provider.get_metadata()["name"],
                )
                return FlextResult[object].fail(f"Web authentication failed: {e}")

        def process_response(
            self,
            response: object,  # FlextWebModels.WebResponse - avoid import
        ) -> FlextResult[object]:
            """Process web response (pass-through for web auth).

            Web auth middleware doesn't need to process responses,
            but this method is required by the middleware protocol.

            Args:
            response: Web response

            Returns:
            FlextResult with unchanged response

            """
            return FlextResult[object].ok(response)

        def _extract_token(self, request: object) -> str | None:
            """Extract authentication token from request.

            Checks in order:
            1. Authorization header (with prefix stripping)
            2. Cookie (if cookie_name configured)

            Args:
            request: Web request

            Returns:
            Extracted token or None if not found

            """
            # Try header first - fast fail if missing
            headers = getattr(request, "headers", {})
            if isinstance(headers, dict) or hasattr(headers, "get"):
                auth_header_value = headers.get(self._header_name)
                if not isinstance(auth_header_value, str):
                    return None
                auth_header = auth_header_value
            else:
                return None

            if auth_header:
                # Strip prefix if present
                if self._token_prefix and auth_header.startswith(
                    f"{self._token_prefix} "
                ):
                    return auth_header[len(self._token_prefix) + 1 :]
                if not self._token_prefix:
                    return auth_header

            # Try cookie if configured
            if self._cookie_name:
                cookies = getattr(request, "cookies", {})
                if isinstance(cookies, dict):
                    token = cookies.get(self._cookie_name)
                    if token:
                        return token

            return None


__all__ = ["FlextAuthMiddleware"]

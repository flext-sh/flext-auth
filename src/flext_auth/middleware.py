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

    auth = FlextAuthMiddleware.HttpAuthMiddleware(FlextAuthJwtProvider(secret="key"))
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

from flext_core import FlextLogger, FlextResult, FlextService, FlextTypes

from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthMiddleware(FlextService):
    """Authentication middleware adapters following FLEXT standards.

    This class provides middleware that adapts FlextAuthBaseProvider implementations
    to work with HTTP client middleware (flext-api) and web application middleware
    (flext-web). Following FLEXT pattern: one class per module with nested middleware classes.
    """

    def execute(self) -> FlextResult[object]:
        """Execute method for FlextService interface.

        FlextAuthMiddleware is a namespace class - use specific middleware classes instead.
        """
        return FlextResult[object].fail(
            "FlextAuthMiddleware is a namespace class - use specific middleware classes like HttpAuthMiddleware"
        )

    class HttpAuthMiddleware:
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
            >>> middleware = FlextAuthMiddleware.HttpAuthMiddleware(
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
            credentials: FlextTypes.Dict | None = None,
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
            self.name = f"HttpAuthMiddleware({provider.get_metadata()['name']})"
            self._provider = provider
            self._credentials = credentials
            self._header_name = header_name
            self._token_prefix = token_prefix
            self._auto_refresh = auto_refresh
            self.logger = FlextLogger(
                f"flext_auth.middleware.http.{provider.get_metadata()['name']}"
            )
            self._current_token: FlextAuthModels.AuthToken | None = None
            self._enabled = True

        def process_request(
            self,
            request: object,  # FlextApiModels.HttpRequest - avoid import
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
                    dict(request.headers) if hasattr(request, "headers") else {}
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
            response: object,  # FlextApiModels.HttpResponse - avoid import
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
            """Ensure we have a valid authentication token.

            This method handles the token lifecycle:
            1. If no token exists, authenticate using credentials
            2. If token exists, validate it
            3. If token is invalid/expired and refresh supported, refresh it
            4. If refresh fails or not supported, re-authenticate

            Returns:
                FlextResult with valid token or error

            """
            # If no token, authenticate
            if not self._current_token:
                if not self._credentials:
                    return FlextResult[FlextAuthModels.AuthToken].fail(
                        "No authentication token and no credentials provided"
                    )

                auth_result = self._provider.authenticate(self._credentials)
                if auth_result.is_failure:
                    return auth_result

                self._current_token = auth_result.unwrap()
                self.logger.info(
                    "Initial authentication successful",
                    provider=self._provider.get_metadata()["name"],
                )
                return FlextResult[FlextAuthModels.AuthToken].ok(self._current_token)

            # Validate current token
            validation_result = self._provider.validate(self._current_token)
            if validation_result.is_success and validation_result.unwrap():
                # Token is valid
                return FlextResult[FlextAuthModels.AuthToken].ok(self._current_token)

            # Token is invalid/expired - try to refresh
            if self._auto_refresh and "refresh" in self._provider.supports():
                self.logger.debug(
                    "Token expired, attempting refresh",
                    provider=self._provider.get_metadata()["name"],
                )

                refresh_result = self._provider.refresh(self._current_token)
                if refresh_result.is_success:
                    self._current_token = refresh_result.unwrap()
                    self.logger.info(
                        "Token refresh successful",
                        provider=self._provider.get_metadata()["name"],
                    )
                    return FlextResult[FlextAuthModels.AuthToken].ok(
                        self._current_token
                    )

            # Refresh failed or not supported - re-authenticate
            if self._credentials:
                self.logger.debug(
                    "Token refresh failed, re-authenticating",
                    provider=self._provider.get_metadata()["name"],
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

    class WebAuthMiddleware:
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
            exclude_paths: FlextTypes.StringList | None = None,
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
            self.name = f"WebAuthMiddleware({provider.get_metadata()['name']})"
            self._provider = provider
            self._header_name = header_name
            self._token_prefix = token_prefix
            self._cookie_name = cookie_name
            self._exclude_paths = exclude_paths or []
            self._require_auth = require_auth
            self.logger = FlextLogger(
                f"flext_auth.middleware.web.{provider.get_metadata()['name']}"
            )
            self._enabled = True

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
            # Try header first
            headers = getattr(request, "headers", {})
            if isinstance(headers, dict):
                auth_header = headers.get(self._header_name, "")
            else:
                # Handle case where headers is a special object (like FastAPI's Headers)
                auth_header = (
                    headers.get(self._header_name, "")
                    if hasattr(headers, "get")
                    else ""
                )

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


__all__ = ["FlextAuthMiddleware"]

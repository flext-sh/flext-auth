"""Unit tests for FlextAuthMiddleware.HttpAuthMiddleware.

Tests the HTTP client authentication middleware adapter that integrates
flext-auth providers with HTTP clients (flext-api).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast
from unittest.mock import MagicMock

from flext_core import FlextResult, FlextTypes

from flext_auth import FlextAuthMiddleware
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthMockProvider(FlextAuthBaseProvider):
    """Mock authentication provider for testing."""

    def __init__(
        self,
        auth_token: str = "mock-access-token",
        *,
        auth_success: bool = True,
        validate_success: bool = True,
        refresh_success: bool = True,
        supports_refresh: bool = True,
    ) -> None:
        """Initialize mock authentication provider."""
        self._auth_token = auth_token
        self._auth_success = auth_success
        self._validate_success = validate_success
        self._refresh_success = refresh_success
        self._supports_refresh = supports_refresh
        self._auth_calls = 0
        self._validate_calls = 0
        self._refresh_calls = 0

    def authenticate(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        self._auth_calls += 1
        if not self._auth_success:
            return FlextResult[FlextAuthModels.AuthToken].fail("Authentication failed")
        token = FlextAuthModels.AuthToken(
            user_id=credentials.get("username", "test-user"),
            token=self._auth_token,
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(seconds=3600),
        )
        return FlextResult[FlextAuthModels.AuthToken].ok(token)

    def validate(self, token: str | FlextAuthModels.AuthToken) -> FlextResult[bool]:
        self._validate_calls += 1
        if not self._validate_success:
            return FlextResult[bool].fail("Validation failed")
        return FlextResult[bool].ok(self._validate_success)

    def refresh(
        self, token: str | FlextAuthModels.AuthToken
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        self._refresh_calls += 1
        if not self._refresh_success:
            return FlextResult[FlextAuthModels.AuthToken].fail("Refresh failed")

        # Get user_id from existing token
        user_id = (
            token.user_id
            if isinstance(token, FlextAuthModels.AuthToken)
            else "test-user"
        )

        new_token = FlextAuthModels.AuthToken(
            user_id=user_id,
            token=f"{self._auth_token}-refreshed",
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(seconds=3600),
        )
        return FlextResult[FlextAuthModels.AuthToken].ok(new_token)

    def revoke(self, token: str | FlextAuthModels.AuthToken) -> FlextResult[None]:
        return FlextResult[None].ok(None)

    def supports(self) -> set[str]:
        capabilities = {"token", "validate"}
        if self._supports_refresh:
            capabilities.add("refresh")
        return capabilities

    def get_metadata(self) -> FlextTypes.Dict:
        return {
            "name": "mock",
            "version": "1.0.0",
            "capabilities": list(self.supports()),
        }


class MockHttpRequest:
    """Mock HTTP request for testing."""

    def __init__(
        self,
        url: str = "https://api.example.com/test",
        method: str = "GET",
        headers: FlextTypes.StringDict | None = None,
    ) -> None:
        """Initialize mock HTTP request."""
        self.url = url
        self.method = method
        self.headers = headers or {}


class TestFlextAuthMiddleware:
    """Test suite for FlextAuthMiddleware.HttpAuthMiddleware."""

    def test_middleware_initialization(self) -> None:
        """Test middleware initialization with provider."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
        )

        assert middleware.name == "FlextAuthMiddleware.HttpAuthMiddleware(mock)"
        assert middleware.is_enabled
        assert middleware._provider == provider
        assert middleware._credentials == {"username": "user", "password": "pass"}
        assert middleware._header_name == "Authorization"
        assert middleware._token_prefix == "Bearer"
        assert middleware._auto_refresh is True

    def test_process_request_success(self) -> None:
        """Test successful request processing with authentication."""
        provider = MockAuthProviderSecond(auth_token="test-token-123")
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
        )

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_success
        processed_request = result.unwrap()
        assert "Authorization" in processed_request.headers
        assert processed_request.headers["Authorization"] == "Bearer test-token-123"
        assert provider._auth_calls == 1
        assert provider._validate_calls == 0  # First auth, no validation yet

    def test_process_request_without_credentials(self) -> None:
        """Test request processing fails without credentials."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials=None,  # No credentials
        )

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_failure
        assert (
            result.error is not None
            and "No authentication token and no credentials provided" in result.error
        )

    def test_process_request_reuses_token(self) -> None:
        """Test middleware reuses valid token for subsequent requests."""
        provider = MockAuthProviderSecond(auth_token="cached-token")
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
        )

        # First request - authenticates
        request1 = MockHttpRequest()
        result1 = middleware.process_request(request1)
        assert result1.is_success
        assert provider._auth_calls == 1

        # Second request - reuses token
        request2 = MockHttpRequest()
        result2 = middleware.process_request(request2)
        assert result2.is_success
        assert provider._auth_calls == 1  # No additional auth
        assert provider._validate_calls == 1  # Validated existing token

    def test_process_request_refreshes_expired_token(self) -> None:
        """Test middleware refreshes expired token."""
        provider = MockAuthProviderSecond(
            auth_token="original-token",
            validate_success=False,  # Token is invalid/expired
            refresh_success=True,
            supports_refresh=True,
        )
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
            auto_refresh=True,
        )

        # First request - authenticates
        request1 = MockHttpRequest()
        result1 = middleware.process_request(request1)
        assert result1.is_success
        assert "Authorization" in result1.unwrap().headers
        assert provider._auth_calls == 1

        # Set provider to fail validation (simulate expiration)
        provider._validate_success = False

        # Second request - should refresh token
        request2 = MockHttpRequest()
        result2 = middleware.process_request(request2)
        assert result2.is_success
        # Token should be refreshed
        assert "refreshed" in result2.unwrap().headers["Authorization"]
        assert provider._refresh_calls == 1

    def test_process_request_reauthenticates_when_refresh_fails(self) -> None:
        """Test middleware re-authenticates when refresh fails."""
        provider = MockAuthProviderSecond(
            auth_token="original-token",
            validate_success=True,
            refresh_success=False,  # Refresh will fail
            supports_refresh=True,
        )
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
            auto_refresh=True,
        )

        # First request - authenticates
        request1 = MockHttpRequest()
        middleware.process_request(request1)
        assert provider._auth_calls == 1

        # Simulate token expiration
        provider._validate_success = False

        # Second request - refresh fails, should re-authenticate
        request2 = MockHttpRequest()
        result2 = middleware.process_request(request2)
        assert result2.is_success
        assert provider._refresh_calls == 1
        assert provider._auth_calls == 2  # Re-authenticated

    def test_process_request_custom_header(self) -> None:
        """Test middleware with custom authorization header."""
        provider = MockAuthProviderSecond(auth_token="api-key-123")
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"api_key": "key"},
            header_name="X-API-Key",
            token_prefix="",  # No prefix
        )

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_success
        processed_request = result.unwrap()
        assert "X-API-Key" in processed_request.headers
        assert processed_request.headers["X-API-Key"] == "api-key-123"

    def test_process_request_with_token_prefix(self) -> None:
        """Test middleware with custom token prefix."""
        provider = MockAuthProviderSecond(auth_token="jwt-token")
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
            token_prefix="JWT",
        )

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_success
        assert result.unwrap().headers["Authorization"] == "JWT jwt-token"

    def test_process_request_disabled_middleware(self) -> None:
        """Test middleware pass-through when disabled."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
        )
        middleware.disable()

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_success
        assert "Authorization" not in result.unwrap().headers
        assert provider._auth_calls == 0  # No authentication performed

    def test_process_response_passthrough(self) -> None:
        """Test response processing is pass-through."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
        )

        mock_response = MagicMock()
        mock_response.status_code = 200

        result = middleware.process_response(mock_response)

        assert result.is_success
        assert result.unwrap() == mock_response

    def test_authentication_failure(self) -> None:
        """Test middleware handles authentication failure."""
        provider = MockAuthProviderSecond(auth_success=False)
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "wrong"},
        )

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_failure
        assert result.error is not None and "Authentication failed" in result.error

    def test_enable_disable_toggle(self) -> None:
        """Test enabling and disabling middleware."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
        )

        assert middleware.is_enabled

        middleware.disable()
        assert not middleware.is_enabled

        middleware.enable()
        assert middleware.is_enabled

    def test_process_request_no_auto_refresh(self) -> None:
        """Test middleware without auto-refresh re-authenticates on expiration."""
        provider = MockAuthProviderSecond(
            auth_token="original-token",
            validate_success=True,
            supports_refresh=True,
        )
        middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
            auto_refresh=False,  # Disable auto-refresh
        )

        # First request - authenticates
        request1 = MockHttpRequest()
        middleware.process_request(request1)
        assert provider._auth_calls == 1

        # Simulate token expiration
        provider._validate_success = False

        # Second request - should re-authenticate (not refresh)
        request2 = MockHttpRequest()
        result2 = middleware.process_request(request2)
        assert result2.is_success
        assert provider._refresh_calls == 0  # No refresh
        assert provider._auth_calls == 2  # Re-authenticated

    def test_multiple_providers_different_middlewares(self) -> None:
        """Test multiple middleware instances with different providers."""
        jwt_provider = FlextAuthMockProvider(auth_token="jwt-token")
        oauth_provider = FlextAuthMockProvider(auth_token="oauth-token")

        jwt_middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=jwt_provider,
            credentials={"username": "user1", "password": "pass1"},
        )

        oauth_middleware = FlextAuthMiddleware.HttpAuthMiddleware(
            provider=oauth_provider,
            credentials={"username": "user2", "password": "pass2"},
        )

        request1 = MockHttpRequest()
        result1 = jwt_middleware.process_request(request1)
        assert "jwt-token" in result1.unwrap().headers["Authorization"]

        request2 = MockHttpRequest()
        result2 = oauth_middleware.process_request(request2)
        assert "oauth-token" in result2.unwrap().headers["Authorization"]


class MockAuthProviderSecond(FlextAuthBaseProvider):
    """Mock authentication provider for testing."""

    def __init__(
        self,
        *,
        validate_success: bool = True,
        validate_result: bool = True,
    ) -> None:
        """Initialize mock authentication provider."""
        self._validate_success = validate_success
        self._validate_result = validate_result
        self._validate_calls = 0

    def authenticate(
        self, credentials: FlextTypes.Dict
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        token = FlextAuthModels.AuthToken(
            user_id=credentials.get("username", "test-user"),
            token="mock-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(seconds=3600),
            is_revoked=False,
        )
        return FlextResult[FlextAuthModels.AuthToken].ok(token)

    def validate(self, token: str | FlextAuthModels.AuthToken) -> FlextResult[bool]:
        self._validate_calls += 1
        if not self._validate_success:
            return FlextResult[bool].fail("Validation error")
        return FlextResult[bool].ok(self._validate_result)

    def refresh(
        self, token: str | FlextAuthModels.AuthToken
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        return FlextResult[FlextAuthModels.AuthToken].fail("Not supported")

    def revoke(self, token: str | FlextAuthModels.AuthToken) -> FlextResult[None]:
        return FlextResult[None].ok(None)

    def supports(self) -> set[str]:
        return {"token", "validate"}

    def get_metadata(self) -> FlextTypes.Dict:
        return {
            "name": "mock-web",
            "version": "1.0.0",
            "capabilities": list(self.supports()),
        }


class MockWebRequest:
    """Mock web request for testing."""

    def __init__(
        self,
        path: str = "/api/test",
        headers: FlextTypes.StringDict | None = None,
        cookies: FlextTypes.StringDict | None = None,
    ) -> None:
        """Initialize mock web request."""
        self.path = path
        self.url = path
        self.headers = headers or {}
        self.cookies = cookies or {}


class TestFlextAuthMiddleware2:
    """Test suite for FlextAuthMiddleware.WebAuthMiddleware."""

    def test_middleware_initialization(self) -> None:
        """Test middleware initialization with provider."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            header_name="Authorization",
            token_prefix="Bearer",
        )

        assert middleware.name == "FlextAuthMiddleware.WebAuthMiddleware(mock-web)"
        assert middleware.is_enabled
        assert middleware._provider == provider
        assert middleware._header_name == "Authorization"
        assert middleware._token_prefix == "Bearer"
        assert middleware._require_auth is True

    def test_process_request_success(self) -> None:
        """Test successful request processing with valid token."""
        provider = MockAuthProviderSecond(validate_success=True, validate_result=True)
        middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=provider)

        request = MockWebRequest(headers={"Authorization": "Bearer valid-token"})
        result = middleware.process_request(request)

        assert result.is_success
        processed_request = result.unwrap()
        assert hasattr(processed_request, "user_context")
        assert processed_request.user_context["authenticated"] is True
        assert processed_request.user_context["provider"] == "mock-web"
        assert provider._validate_calls == 1

    def test_process_request_missing_token(self) -> None:
        """Test request processing fails when token is missing."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            require_auth=True,
        )

        request = MockWebRequest()  # No auth header
        result = middleware.process_request(request)

        assert result.is_failure
        assert "Authentication required" in (result.error or "")
        assert "No token found" in (result.error or "")

    def test_process_request_invalid_token(self) -> None:
        """Test request processing fails with invalid token."""
        provider = MockAuthProviderSecond(
            validate_success=True,
            validate_result=False,  # Token is invalid
        )
        middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=provider)

        request = MockWebRequest(headers={"Authorization": "Bearer invalid-token"})
        result = middleware.process_request(request)

        assert result.is_failure
        assert "Invalid or expired token" in (result.error or "")

    def test_process_request_validation_error(self) -> None:
        """Test request processing fails when validation errors."""
        provider = MockAuthProviderSecond(
            validate_success=False,  # Validation fails
        )
        middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=provider)

        request = MockWebRequest(headers={"Authorization": "Bearer token"})
        result = middleware.process_request(request)

        assert result.is_failure
        assert "Token validation failed" in (result.error or "")

    def test_process_request_excluded_path(self) -> None:
        """Test middleware skips authentication for excluded paths."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            exclude_paths=["/health", "/docs", "/metrics"],
        )

        # Test health endpoint (excluded)
        health_request = MockWebRequest(path="/health")
        health_result = middleware.process_request(health_request)
        assert health_result.is_success
        assert not hasattr(health_result.unwrap(), "user_context")
        assert provider._validate_calls == 0

        # Test docs endpoint (excluded)
        docs_request = MockWebRequest(path="/docs/api")
        docs_result = middleware.process_request(docs_request)
        assert docs_result.is_success
        assert provider._validate_calls == 0

        # Test regular endpoint (not excluded)
        api_request = MockWebRequest(
            path="/api/users", headers={"Authorization": "Bearer token"}
        )
        api_result = middleware.process_request(api_request)
        assert api_result.is_success
        assert provider._validate_calls == 1  # Should validate

    def test_process_request_optional_auth(self) -> None:
        """Test middleware allows requests without auth when not required."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            require_auth=False,  # Auth is optional
        )

        request = MockWebRequest()  # No auth header
        result = middleware.process_request(request)

        assert result.is_success
        assert not hasattr(result.unwrap(), "user_context")
        assert provider._validate_calls == 0

    def test_process_request_custom_header(self) -> None:
        """Test middleware with custom authorization header."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            header_name="X-API-Key",
            token_prefix="",  # No prefix
        )

        request = MockWebRequest(headers={"X-API-Key": "api-key-123"})
        result = middleware.process_request(request)

        assert result.is_success
        assert hasattr(result.unwrap(), "user_context")
        assert result.unwrap().user_context["token"] == "api-key-123"

    def test_process_request_token_from_cookie(self) -> None:
        """Test middleware extracts token from cookie."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            cookie_name="auth_token",
        )

        request = MockWebRequest(cookies={"auth_token": "cookie-token-123"})
        result = middleware.process_request(request)

        assert result.is_success
        assert hasattr(result.unwrap(), "user_context")
        assert result.unwrap().user_context["token"] == "cookie-token-123"

    def test_process_request_header_priority_over_cookie(self) -> None:
        """Test middleware prioritizes header token over cookie."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            cookie_name="auth_token",
        )

        request = MockWebRequest(
            headers={"Authorization": "Bearer header-token"},
            cookies={"auth_token": "cookie-token"},
        )
        result = middleware.process_request(request)

        assert result.is_success
        # Should use header token
        assert result.unwrap().user_context["token"] == "header-token"

    def test_process_request_strips_token_prefix(self) -> None:
        """Test middleware correctly strips token prefix."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            token_prefix="Bearer",
        )

        request = MockWebRequest(headers={"Authorization": "Bearer my-token-value"})
        result = middleware.process_request(request)

        assert result.is_success
        # Token should have prefix stripped
        assert result.unwrap().user_context["token"] == "my-token-value"

    def test_process_request_custom_token_prefix(self) -> None:
        """Test middleware with custom token prefix."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            token_prefix="JWT",
        )

        request = MockWebRequest(headers={"Authorization": "JWT jwt-token-123"})
        result = middleware.process_request(request)

        assert result.is_success
        assert result.unwrap().user_context["token"] == "jwt-token-123"

    def test_process_request_disabled_middleware(self) -> None:
        """Test middleware pass-through when disabled."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=provider)
        middleware.disable()

        request = MockWebRequest(headers={"Authorization": "Bearer token"})
        result = middleware.process_request(request)

        assert result.is_success
        assert not hasattr(result.unwrap(), "user_context")
        assert provider._validate_calls == 0

    def test_process_response_passthrough(self) -> None:
        """Test response processing is pass-through."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=provider)

        mock_response = MagicMock()
        mock_response.status_code = 200

        result = middleware.process_response(mock_response)

        assert result.is_success
        assert result.unwrap() == mock_response

    def test_enable_disable_toggle(self) -> None:
        """Test enabling and disabling middleware."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=provider)

        assert middleware.is_enabled

        middleware.disable()
        assert not middleware.is_enabled

        middleware.enable()
        assert middleware.is_enabled

    def test_process_request_multiple_excluded_paths(self) -> None:
        """Test middleware handles multiple excluded path patterns."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=provider,
            exclude_paths=["/health", "/metrics", "/api/public"],
        )

        excluded_paths = ["/health", "/metrics", "/api/public/info"]
        for path in excluded_paths:
            request = MockWebRequest(path=path)
            result = middleware.process_request(request)
            assert result.is_success
            assert not hasattr(result.unwrap(), "user_context")

    def test_user_context_structure(self) -> None:
        """Test user context has expected structure."""
        provider = MockAuthProviderSecond()
        middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=provider)

        request = MockWebRequest(headers={"Authorization": "Bearer test-token"})
        result = middleware.process_request(request)

        assert result.is_success
        user_context = result.unwrap().user_context

        assert "authenticated" in user_context
        assert user_context["authenticated"] is True
        assert "provider" in user_context
        assert user_context["provider"] == "mock-web"
        assert "token" in user_context
        assert user_context["token"] == "test-token"

    def test_multiple_middlewares_different_providers(self) -> None:
        """Test multiple middleware instances with different providers."""

        class JwtMockProvider(FlextAuthMockProvider):
            def get_metadata(self) -> FlextTypes.Dict:
                return {
                    "name": "jwt",
                    "version": "1.0.0",
                    "capabilities": ["token", "validate"],
                }

        class OAuth2MockProvider(FlextAuthMockProvider):
            def get_metadata(self) -> FlextTypes.Dict:
                return {
                    "name": "oauth2",
                    "version": "1.0.0",
                    "capabilities": ["token", "validate"],
                }

        jwt_provider = JwtMockProvider()
        oauth_provider = OAuth2MockProvider()

        jwt_middleware = FlextAuthMiddleware.WebAuthMiddleware(provider=jwt_provider)
        oauth_middleware = FlextAuthMiddleware.WebAuthMiddleware(
            provider=oauth_provider
        )

        request1 = MockWebRequest(headers={"Authorization": "Bearer jwt-token"})
        result1 = jwt_middleware.process_request(request1)
        assert result1.is_success
        authenticated_request1 = cast("MockWebRequest", result1.unwrap())
        assert authenticated_request1.user_context["provider"] == "jwt"

        request2 = MockWebRequest(headers={"Authorization": "Bearer oauth-token"})
        result2 = oauth_middleware.process_request(request2)
        assert result2.is_success
        authenticated_request2 = cast("MockWebRequest", result2.unwrap())
        assert authenticated_request2.user_context["provider"] == "oauth2"

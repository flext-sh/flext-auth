"""Unit tests for WebAuthMiddleware.

Tests the web application authentication middleware adapter that integrates
flext-auth providers with web applications (flext-web FastAPI/Flask).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from unittest.mock import MagicMock

from flext_auth import WebAuthMiddleware
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import BaseAuthProvider
from flext_core import FlextResult


class MockAuthProvider(BaseAuthProvider):
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
        self, credentials: dict[str, object]
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        from datetime import UTC, datetime, timedelta

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

    def get_metadata(self) -> dict[str, object]:
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
        headers: dict[str, str] | None = None,
        cookies: dict[str, str] | None = None,
    ) -> None:
        """Initialize mock web request."""
        self.path = path
        self.url = path
        self.headers = headers or {}
        self.cookies = cookies or {}


class TestWebAuthMiddleware:
    """Test suite for WebAuthMiddleware."""

    def test_middleware_initialization(self) -> None:
        """Test middleware initialization with provider."""
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
            provider=provider,
            header_name="Authorization",
            token_prefix="Bearer",
        )

        assert middleware.name == "WebAuthMiddleware(mock-web)"
        assert middleware.is_enabled
        assert middleware._provider == provider
        assert middleware._header_name == "Authorization"
        assert middleware._token_prefix == "Bearer"
        assert middleware._require_auth is True

    def test_process_request_success(self) -> None:
        """Test successful request processing with valid token."""
        provider = MockAuthProvider(validate_success=True, validate_result=True)
        middleware = WebAuthMiddleware(provider=provider)

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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider(
            validate_success=True,
            validate_result=False,  # Token is invalid
        )
        middleware = WebAuthMiddleware(provider=provider)

        request = MockWebRequest(headers={"Authorization": "Bearer invalid-token"})
        result = middleware.process_request(request)

        assert result.is_failure
        assert "Invalid or expired token" in (result.error or "")

    def test_process_request_validation_error(self) -> None:
        """Test request processing fails when validation errors."""
        provider = MockAuthProvider(
            validate_success=False,  # Validation fails
        )
        middleware = WebAuthMiddleware(provider=provider)

        request = MockWebRequest(headers={"Authorization": "Bearer token"})
        result = middleware.process_request(request)

        assert result.is_failure
        assert "Token validation failed" in (result.error or "")

    def test_process_request_excluded_path(self) -> None:
        """Test middleware skips authentication for excluded paths."""
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
            provider=provider,
            token_prefix="JWT",
        )

        request = MockWebRequest(headers={"Authorization": "JWT jwt-token-123"})
        result = middleware.process_request(request)

        assert result.is_success
        assert result.unwrap().user_context["token"] == "jwt-token-123"

    def test_process_request_disabled_middleware(self) -> None:
        """Test middleware pass-through when disabled."""
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(provider=provider)
        middleware.disable()

        request = MockWebRequest(headers={"Authorization": "Bearer token"})
        result = middleware.process_request(request)

        assert result.is_success
        assert not hasattr(result.unwrap(), "user_context")
        assert provider._validate_calls == 0

    def test_process_response_passthrough(self) -> None:
        """Test response processing is pass-through."""
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(provider=provider)

        mock_response = MagicMock()
        mock_response.status_code = 200

        result = middleware.process_response(mock_response)

        assert result.is_success
        assert result.unwrap() == mock_response

    def test_enable_disable_toggle(self) -> None:
        """Test enabling and disabling middleware."""
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(provider=provider)

        assert middleware.is_enabled

        middleware.disable()
        assert not middleware.is_enabled

        middleware.enable()
        assert middleware.is_enabled

    def test_process_request_multiple_excluded_paths(self) -> None:
        """Test middleware handles multiple excluded path patterns."""
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = WebAuthMiddleware(provider=provider)

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

        class JwtMockProvider(MockAuthProvider):
            def get_metadata(self) -> dict[str, object]:
                return {
                    "name": "jwt",
                    "version": "1.0.0",
                    "capabilities": ["token", "validate"],
                }

        class OAuth2MockProvider(MockAuthProvider):
            def get_metadata(self) -> dict[str, object]:
                return {
                    "name": "oauth2",
                    "version": "1.0.0",
                    "capabilities": ["token", "validate"],
                }

        jwt_provider = JwtMockProvider()
        oauth_provider = OAuth2MockProvider()

        jwt_middleware = WebAuthMiddleware(provider=jwt_provider)
        oauth_middleware = WebAuthMiddleware(provider=oauth_provider)

        request1 = MockWebRequest(headers={"Authorization": "Bearer jwt-token"})
        result1 = jwt_middleware.process_request(request1)
        assert result1.is_success
        assert result1.unwrap().user_context["provider"] == "jwt"

        request2 = MockWebRequest(headers={"Authorization": "Bearer oauth-token"})
        result2 = oauth_middleware.process_request(request2)
        assert result2.is_success
        assert result2.unwrap().user_context["provider"] == "oauth2"

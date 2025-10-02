"""Unit tests for HttpAuthMiddleware.

Tests the HTTP client authentication middleware adapter that integrates
flext-auth providers with HTTP clients (flext-api).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Any
from unittest.mock import MagicMock

from flext_auth import HttpAuthMiddleware
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import BaseAuthProvider
from flext_core import FlextResult


class MockAuthProvider(BaseAuthProvider):
    """Mock authentication provider for testing."""

    def __init__(
        self,
        auth_token: str = "mock-access-token",
        auth_success: bool = True,
        validate_success: bool = True,
        refresh_success: bool = True,
        supports_refresh: bool = True,
    ) -> None:
        self._auth_token = auth_token
        self._auth_success = auth_success
        self._validate_success = validate_success
        self._refresh_success = refresh_success
        self._supports_refresh = supports_refresh
        self._auth_calls = 0
        self._validate_calls = 0
        self._refresh_calls = 0

    def authenticate(
        self, credentials: dict[str, Any]
    ) -> FlextResult[FlextAuthModels.AuthToken]:
        from datetime import UTC, datetime, timedelta

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
        from datetime import UTC, datetime, timedelta

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

    def get_metadata(self) -> dict[str, Any]:
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
        headers: dict[str, str] | None = None,
    ) -> None:
        self.url = url
        self.method = method
        self.headers = headers or {}


class TestHttpAuthMiddleware:
    """Test suite for HttpAuthMiddleware."""

    def test_middleware_initialization(self) -> None:
        """Test middleware initialization with provider."""
        provider = MockAuthProvider()
        middleware = HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "pass"},
        )

        assert middleware.name == "HttpAuthMiddleware(mock)"
        assert middleware.is_enabled
        assert middleware._provider == provider
        assert middleware._credentials == {"username": "user", "password": "pass"}
        assert middleware._header_name == "Authorization"
        assert middleware._token_prefix == "Bearer"
        assert middleware._auto_refresh is True

    def test_process_request_success(self) -> None:
        """Test successful request processing with authentication."""
        provider = MockAuthProvider(auth_token="test-token-123")
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = HttpAuthMiddleware(
            provider=provider,
            credentials=None,  # No credentials
        )

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_failure
        assert "No authentication token and no credentials provided" in result.error

    def test_process_request_reuses_token(self) -> None:
        """Test middleware reuses valid token for subsequent requests."""
        provider = MockAuthProvider(auth_token="cached-token")
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider(
            auth_token="original-token",
            validate_success=False,  # Token is invalid/expired
            refresh_success=True,
            supports_refresh=True,
        )
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider(
            auth_token="original-token",
            validate_success=True,
            refresh_success=False,  # Refresh will fail
            supports_refresh=True,
        )
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider(auth_token="api-key-123")
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider(auth_token="jwt-token")
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider()
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider(auth_success=False)
        middleware = HttpAuthMiddleware(
            provider=provider,
            credentials={"username": "user", "password": "wrong"},
        )

        request = MockHttpRequest()
        result = middleware.process_request(request)

        assert result.is_failure
        assert "Authentication failed" in result.error

    def test_enable_disable_toggle(self) -> None:
        """Test enabling and disabling middleware."""
        provider = MockAuthProvider()
        middleware = HttpAuthMiddleware(
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
        provider = MockAuthProvider(
            auth_token="original-token",
            validate_success=True,
            supports_refresh=True,
        )
        middleware = HttpAuthMiddleware(
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
        jwt_provider = MockAuthProvider(auth_token="jwt-token")
        oauth_provider = MockAuthProvider(auth_token="oauth-token")

        jwt_middleware = HttpAuthMiddleware(
            provider=jwt_provider,
            credentials={"username": "user1", "password": "pass1"},
        )

        oauth_middleware = HttpAuthMiddleware(
            provider=oauth_provider,
            credentials={"username": "user2", "password": "pass2"},
        )

        request1 = MockHttpRequest()
        result1 = jwt_middleware.process_request(request1)
        assert "jwt-token" in result1.unwrap().headers["Authorization"]

        request2 = MockHttpRequest()
        result2 = oauth_middleware.process_request(request2)
        assert "oauth-token" in result2.unwrap().headers["Authorization"]

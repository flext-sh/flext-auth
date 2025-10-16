"""Tests for OAuth2/OIDC HTTP client integration.

Tests for HTTP client functionality in OAuth2 and OIDC providers:
- Token endpoint requests (authorization code, client credentials, password, refresh)
- UserInfo endpoint requests
- Error handling for HTTP failures
- OAuth2 error response parsing

Copyright (c) 2025 FLEXT Team. All rights reserved.
"""

from __future__ import annotations

from flext_core import FlextTypes
from pytest_httpx import HTTPXMock

from flext_auth.providers import FlextAuthOAuth2Provider, FlextAuthOidcProvider

# ===== OAuth2 Token Endpoint Tests =====


class TestOAuth2TokenEndpoint:
    """Tests for OAuth2 token endpoint HTTP integration."""

    def test_authorization_code_flow_success(self, httpx_mock: HTTPXMock) -> None:
        """Test successful authorization code exchange."""
        # Mock token endpoint response
        httpx_mock.add_response(
            method="POST",
            url="https://auth.example.com/token",
            json={
                "access_token": "test_access_token_abc123",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test_refresh_token_xyz789",
                "scope": "openid profile email",
            },
            status_code=200,
        )

        # Create provider
        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "redirect_uri": "https://app.example.com/callback",
            "flow": "authorization_code",
            "use_pkce": False,
        }
        provider = FlextAuthOAuth2Provider(config)

        # Authenticate with authorization code
        result = provider.authenticate({
            "code": "test_auth_code",
            "state": "test_state",
        })

        assert result.is_success
        token = result.unwrap()
        assert token.token == "test_access_token_abc123"
        assert token.token_type == "bearer"
        assert token.refresh_token == "test_refresh_token_xyz789"
        assert token.scope == "openid profile email"

    def test_authorization_code_flow_with_pkce(self, httpx_mock: HTTPXMock) -> None:
        """Test authorization code exchange with PKCE."""
        # Mock token endpoint response
        httpx_mock.add_response(
            method="POST",
            url="https://auth.example.com/token",
            json={
                "access_token": "test_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
            },
            status_code=200,
        )

        config = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "redirect_uri": "https://app.example.com/callback",
            "flow": "authorization_code",
            "use_pkce": True,
        }
        provider = FlextAuthOAuth2Provider(config)

        # Generate PKCE challenge
        code_verifier, _code_challenge = provider.generate_pkce_challenge()

        # Authenticate with authorization code and PKCE verifier
        result = provider.authenticate({
            "code": "test_auth_code",
            "state": "test_state",
            "code_verifier": code_verifier,
        })

        assert result.is_success

    def test_client_credentials_flow_success(self, httpx_mock: HTTPXMock) -> None:
        """Test successful client credentials flow."""
        # Mock token endpoint response
        httpx_mock.add_response(
            method="POST",
            url="https://auth.example.com/token",
            json={
                "access_token": "test_access_token_client",
                "token_type": "Bearer",
                "expires_in": 7200,
                "scope": "api.read api.write",
            },
            status_code=200,
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "flow": "client_credentials",
        }
        provider = FlextAuthOAuth2Provider(config)

        # Authenticate with client credentials
        result = provider.authenticate({})

        assert result.is_success
        token = result.unwrap()
        assert token.token == "test_access_token_client"
        assert token.token_type == "bearer"

    def test_password_flow_success(self, httpx_mock: HTTPXMock) -> None:
        """Test successful password flow."""
        # Mock token endpoint response
        httpx_mock.add_response(
            method="POST",
            url="https://auth.example.com/token",
            json={
                "access_token": "test_access_token_password",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test_refresh_token",
            },
            status_code=200,
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "flow": "password",
        }
        provider = FlextAuthOAuth2Provider(config)

        # Authenticate with username/password
        result = provider.authenticate({
            "username": "testuser",
            "password": "testpassword",
        })

        assert result.is_success
        token = result.unwrap()
        assert token.token == "test_access_token_password"

    def test_refresh_token_success(self, httpx_mock: HTTPXMock) -> None:
        """Test successful token refresh."""
        # Mock token endpoint response
        httpx_mock.add_response(
            method="POST",
            url="https://auth.example.com/token",
            json={
                "access_token": "test_new_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test_new_refresh_token",
            },
            status_code=200,
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "flow": "authorization_code",
        }
        provider = FlextAuthOAuth2Provider(config)

        # Refresh token
        result = provider.refresh("test_old_refresh_token")

        assert result.is_success
        new_token = result.unwrap()
        assert new_token.token == "test_new_access_token"
        assert new_token.refresh_token == "test_new_refresh_token"

    def test_oauth2_error_response(self, httpx_mock: HTTPXMock) -> None:
        """Test OAuth2 error response parsing."""
        # Mock OAuth2 error response
        httpx_mock.add_response(
            method="POST",
            url="https://auth.example.com/token",
            json={
                "error": "invalid_grant",
                "error_description": "Authorization code expired",
                "error_uri": "https://docs.example.com/oauth/errors",
            },
            status_code=400,
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "flow": "authorization_code",
            "use_pkce": False,
        }
        provider = FlextAuthOAuth2Provider(config)

        # Attempt authentication
        result = provider.authenticate({
            "code": "expired_code",
            "state": "test_state",
        })

        assert result.is_failure
        assert result.error is not None and "invalid_grant" in result.error
        assert result.error is not None and "Authorization code expired" in result.error

    def test_http_connection_error(self, httpx_mock: HTTPXMock) -> None:
        """Test HTTP connection error handling."""
        # Mock connection error
        httpx_mock.add_exception(
            Exception("Connection refused"),
            url="https://auth.example.com/token",
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "flow": "client_credentials",
        }
        provider = FlextAuthOAuth2Provider(config)

        # Attempt authentication
        result = provider.authenticate({})

        assert result.is_failure
        assert (
            result.error is not None and "error" in result.error.lower()
        ) or "connection" in result.error.lower()

    def test_http_500_error(self, httpx_mock: HTTPXMock) -> None:
        """Test HTTP 500 server error handling with retry logic."""
        # Mock 500 error - register it 4 times for the retry attempts
        # The retry logic makes up to 4 attempts (1 initial + 3 retries)
        for _ in range(4):
            httpx_mock.add_response(
                method="POST",
                url="https://auth.example.com/token",
                status_code=500,
                text="Internal Server Error",
            )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "flow": "client_credentials",
        }
        provider = FlextAuthOAuth2Provider(config)

        # Attempt authentication - will retry on 500 error
        result = provider.authenticate({})

        assert result.is_failure
        # Check that the error message contains useful information about the failure
        assert result.error is not None
        # The error should mention either "500", "Internal Server Error", or "failed"
        assert any(
            keyword in result.error
            for keyword in ["500", "Internal Server Error", "failed", "Request failed"]
        )


# ===== OIDC UserInfo Endpoint Tests =====


class TestOidcUserInfoEndpoint:
    """Tests for OIDC UserInfo endpoint HTTP integration."""

    def test_userinfo_success(self, httpx_mock: HTTPXMock) -> None:
        """Test successful UserInfo endpoint request."""
        # Mock UserInfo endpoint response
        httpx_mock.add_response(
            method="GET",
            url="https://auth.example.com/userinfo",
            json={
                "sub": "248289761001",
                "name": "Jane Doe",
                "given_name": "Jane",
                "family_name": "Doe",
                "email": "janedoe@example.com",
                "email_verified": True,
                "picture": "https://example.com/janedoe/photo.jpg",
            },
            status_code=200,
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
        }
        provider = FlextAuthOidcProvider(config)

        # Fetch UserInfo
        result = provider.get_userinfo("test_access_token")

        assert result.is_success
        userinfo = result.unwrap()
        assert userinfo["sub"] == "248289761001"
        assert userinfo["name"] == "Jane Doe"
        assert userinfo["email"] == "janedoe@example.com"
        assert userinfo["email_verified"] is True

    def test_userinfo_missing_sub(self, httpx_mock: HTTPXMock) -> None:
        """Test UserInfo response missing required 'sub' claim."""
        # Mock invalid UserInfo response
        httpx_mock.add_response(
            method="GET",
            url="https://auth.example.com/userinfo",
            json={
                "name": "Jane Doe",
                "email": "janedoe@example.com",
            },
            status_code=200,
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
        }
        provider = FlextAuthOidcProvider(config)

        # Fetch UserInfo
        result = provider.get_userinfo("test_access_token")

        assert result.is_failure
        assert result.error is not None and "sub" in result.error

    def test_userinfo_401_unauthorized(self, httpx_mock: HTTPXMock) -> None:
        """Test UserInfo endpoint 401 Unauthorized error."""
        # Mock 401 error
        httpx_mock.add_response(
            method="GET",
            url="https://auth.example.com/userinfo",
            status_code=401,
            text="Unauthorized",
        )

        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            "userinfo_endpoint": "https://auth.example.com/userinfo",
        }
        provider = FlextAuthOidcProvider(config)

        # Fetch UserInfo
        result = provider.get_userinfo("invalid_token")

        assert result.is_failure
        assert (
            result.error is not None and "401" in result.error
        ) or "failed" in result.error.lower()

    def test_userinfo_no_endpoint_configured(self) -> None:
        """Test UserInfo request when endpoint not configured."""
        config: FlextTypes.Dict = {
            "client_id": "test-client",
            "client_secret": "test-secret",
            "issuer": "https://auth.example.com",
            "token_endpoint": "https://auth.example.com/token",
            # No userinfo_endpoint configured
        }
        provider = FlextAuthOidcProvider(config)

        # Fetch UserInfo
        result = provider.get_userinfo("test_access_token")

        assert result.is_failure
        assert result.error is not None and "not configured" in result.error

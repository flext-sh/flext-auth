"""Tests for token real flows in authentication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from flext_auth.middleware import FlextAuthMiddleware
from flext_auth.models import FlextAuthModels as m
from flext_auth.protocols import FlextAuthProtocols as p
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.kerberos import FlextAuthKerberosProvider
from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider
from flext_core import r


class HttpRequest:
    """Minimal HTTP request fixture for middleware tests."""

    def __init__(self) -> None:
        """Initialize with empty headers."""
        self.headers: dict[str, str] = {}


class _BaseProviderForTokenTests(FlextAuthBaseProvider):
    def authenticate(
        self,
        credentials: m.CredentialValidation,
    ) -> r[p.Auth.TokenProtocol]:
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not used in token tests")

    def validate(
        self,
        token: str,
    ) -> r[bool]:
        return self._decode_token_claims(token).map(lambda _claims: True)

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-test-base"


class _MiddlewareRefreshProviderForTokenTests(FlextAuthBaseProvider):
    def __init__(self) -> None:
        super().__init__(
            config={
                "secret_key": "middleware-refresh-secret-for-tests-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 10,
            },
        )
        self.refresh_called = False

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-test-middleware-refresh"

    def authenticate(
        self,
        credentials: m.CredentialValidation,
    ) -> r[p.Auth.TokenProtocol]:
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not used in token tests")

    def validate(
        self,
        token: str,
    ) -> r[bool]:
        _ = token
        return r[bool].fail("Refresh source token is invalid")

    def refresh(
        self,
        token: str,
    ) -> r[p.Auth.TokenProtocol]:
        _ = token
        self.refresh_called = True
        refreshed = m.Auth.AuthToken(
            identity_id="middleware-user",
            token="refreshed-access-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            refresh_token="next-refresh-token",
        )
        return r[p.Auth.TokenProtocol].ok(refreshed)


class _KerberosProviderForTokenTests(FlextAuthKerberosProvider):
    def authenticate(
        self,
        credentials: m.CredentialValidation,
    ) -> r[p.Auth.TokenProtocol]:
        _ = credentials
        return r[p.Auth.TokenProtocol].fail("Not used in token tests")

    def validate(
        self,
        token: str,
    ) -> r[bool]:
        return self.validate_token(token).map(lambda _identity: True)

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-test-kerberos"


class TestTokenRealFlows:
    """Tests for real-world authentication token flows including refresh and validation."""

    def test_base_provider_generate_token_with_real_jwt_claims(self) -> None:
        provider = _BaseProviderForTokenTests(
            config={
                "secret_key": "base-provider-secret-for-token-tests-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 30,
            },
        )

        generate_token = (
            provider.generate_token if hasattr(provider, "generate_token") else None
        )
        assert callable(generate_token)
        generate_token_callable = generate_token

        token_result = generate_token_callable(
            payload={
                "identity_id": "base-token-user",
                "name": "Base Token User",
                "roles": ["user"],
            },
            expiry_minutes=5,
        )

        assert token_result.is_success
        claims_result = provider._decode_token_claims(token_result.value)
        assert claims_result.is_success
        claims = claims_result.value
        assert claims["sub"] == "base-token-user"
        assert claims["name"] == "Base Token User"
        assert claims["token_type"] == "access"

    def test_base_provider_refresh_valid_token_emits_new_token(self) -> None:
        provider = _BaseProviderForTokenTests(
            config={
                "secret_key": "base-provider-refresh-secret-for-tests-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 15,
            },
        )

        issued = provider.generate_token_for_user(
            user={
                "identity_id": "refresh-user",
                "name": "Refresh User",
                "contact": "refresh@example.com",
                "roles": ["admin"],
            },
            token_type="refresh",
            expiry_minutes=10,
        )
        assert issued.is_success

        refresh_result = provider.refresh(issued.value)

        assert refresh_result.is_success
        refreshed = refresh_result.value
        assert refreshed.user_id == "refresh-user"
        assert refreshed.token != issued.value
        assert refreshed.expires_at > datetime.now(UTC)

    def test_middleware_refresh_rejects_invalid_refresh_source_token(self) -> None:
        provider = _MiddlewareRefreshProviderForTokenTests()
        middleware = FlextAuthMiddleware.FlextWebAuthMiddleware(provider)
        middleware._current_token = m.Auth.AuthToken(
            identity_id="middleware-user",
            token="expired-access-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            refresh_token="refresh-source-token",
        )

        request = HttpRequest()

        result = middleware.process_request(request)

        assert result.is_failure
        assert provider.refresh_called is False
        assert "invalid" in (result.error or "").lower()

    def test_kerberos_validate_token_returns_honest_error_without_validator(
        self,
    ) -> None:
        provider = _KerberosProviderForTokenTests(
            config={
                "realm": "EXAMPLE.COM",
                "kdc": "kdc.example.com",
                "service_principal": "HTTP/api.example.com@EXAMPLE.COM",
            },
        )

        result = provider.validate_token("opaque-kerberos-ticket")

        assert result.is_failure
        error = (result.error or "").lower()
        assert "kerberos" in error
        assert "validator" in error or "gssapi" in error

    def test_oauth2_validate_token_uses_authorization_server_introspection(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        provider = FlextAuthOAuth2Provider(
            {
                "client_id": "oauth-test-client",
                "client_secret": "oauth-test-secret",
                "token_endpoint": "https://auth.example.com/token",
                "introspection_endpoint": "https://auth.example.com/introspect",
                "token_endpoint_auth_method": "client_secret_post",
            },
        )

        call_count = {"count": 0}

        def _fake_introspect(token: str) -> r[dict[str, object]]:
            call_count["count"] += 1
            assert token == "opaque-oauth2-token"
            return r[dict[str, object]].ok(
                {
                    "active": True,
                    "sub": "oauth-user-123",
                    "username": "oauth-user",
                    "email": "oauth@example.com",
                    "scope": "profile email",
                },
            )

        monkeypatch.setattr(
            provider,
            "_introspect_token",
            _fake_introspect,
            raising=False,
        )

        result = provider.validate_token("opaque-oauth2-token")

        assert call_count["count"] == 1
        assert result.is_success
        identity = result.value
        assert identity.id == "oauth-user-123"
        assert identity.name == "oauth-user"
        assert identity.contact == "oauth@example.com"

    def test_oauth2_validate_token_fails_when_introspection_reports_inactive(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        provider = FlextAuthOAuth2Provider(
            {
                "client_id": "oauth-test-client",
                "client_secret": "oauth-test-secret",
                "token_endpoint": "https://auth.example.com/token",
                "introspection_endpoint": "https://auth.example.com/introspect",
                "token_endpoint_auth_method": "client_secret_post",
            },
        )

        monkeypatch.setattr(
            provider,
            "_introspect_token",
            lambda _token: r[dict[str, object]].ok({"active": False}),
            raising=False,
        )

        result = provider.validate_token("inactive-token")

        assert result.is_failure
        assert "inactive" in (result.error or "").lower()

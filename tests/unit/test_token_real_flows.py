from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import override

import pytest
from flext_core import r
from flext_tests import tm

from flext_auth import FlextAuthMiddleware, m, p
from flext_auth.protocols import FlextAuthBaseProvider
from flext_auth.providers.kerberos import FlextAuthKerberosProvider
from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider


class _HttpRequest:
    def __init__(self) -> None:
        self.headers: dict[str, str] = {}


class _BaseProviderForTokenTests(FlextAuthBaseProvider):
    @override
    def authenticate(self, credentials: m.Auth.CredentialValidation) -> r[p.Auth.Token]:
        _ = credentials
        return r[p.Auth.Token].fail("Not used in token tests")

    @override
    def validate(self, token: str) -> r[bool]:
        return self._decode_token_claims(token).map(lambda _claims: True)


class _MiddlewareRefreshProviderForTokenTests(FlextAuthBaseProvider):
    def __init__(self) -> None:
        super().__init__(
            config={
                "secret_key": "middleware-refresh-secret-for-tests-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 10,
            }
        )
        self.refresh_called = False

    @override
    def authenticate(self, credentials: m.Auth.CredentialValidation) -> r[p.Auth.Token]:
        _ = credentials
        return r[p.Auth.Token].fail("Not used in token tests")

    @override
    def validate(self, token: str) -> r[bool]:
        _ = token
        return r[bool].fail("Refresh source token is invalid")

    @override
    def refresh(self, token: str) -> r[p.Auth.Token]:
        _ = token
        self.refresh_called = True
        refreshed = m.Auth.AuthToken(
            identity_id="middleware-user",
            token="refreshed-access-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            session_id="",
            is_revoked=False,
            refresh_token="next-refresh-token",
        )
        return r[p.Auth.Token].ok(refreshed)


class _KerberosProviderForTokenTests(FlextAuthKerberosProvider):
    @override
    def authenticate(self, credentials: m.Auth.CredentialValidation) -> r[p.Auth.Token]:
        _ = credentials
        return r[p.Auth.Token].fail("Not used in token tests")

    @override
    def validate(self, token: str) -> r[bool]:
        return self.validate_token(token).map(lambda _identity: True)


class TestTokenRealFlows:
    def test_base_provider_generate_token_with_real_jwt_claims(self) -> None:
        provider = _BaseProviderForTokenTests(
            config={
                "secret_key": "base-provider-secret-for-token-tests-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 30,
            }
        )
        generate_token = (
            provider.generate_token if hasattr(provider, "generate_token") else None
        )
        tm.that(callable(generate_token), eq=True)
        if not callable(generate_token):
            msg = "provider must expose generate_token"
            raise AssertionError(msg)
        token_result = generate_token(
            payload={
                "identity_id": "base-token-user",
                "name": "Base Token User",
                "roles": ["user"],
            },
            expiry_minutes=5,
        )
        tm.ok(token_result)
        claims_result = provider._decode_token_claims(str(token_result.value))
        tm.ok(claims_result)

    def test_base_provider_refresh_valid_token_emits_new_token(self) -> None:
        provider = _BaseProviderForTokenTests(
            config={
                "secret_key": "base-provider-refresh-secret-for-tests-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 15,
            }
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
        tm.ok(issued)
        refresh_result = provider.refresh(str(issued.value))
        tm.ok(refresh_result)

    def test_middleware_refresh_rejects_invalid_refresh_source_token(self) -> None:
        provider = _MiddlewareRefreshProviderForTokenTests()
        middleware = FlextAuthMiddleware.FlextWebAuthMiddleware(provider)
        middleware._current_token = m.Auth.AuthToken(
            identity_id="middleware-user",
            token="expired-access-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            session_id="",
            is_revoked=False,
            refresh_token="refresh-source-token",
        )
        request = _HttpRequest()
        result = middleware.process_request(request)
        tm.fail(result, contains="invalid")
        tm.that(provider.refresh_called, eq=False)

    def test_kerberos_validate_token_returns_honest_error_without_validator(
        self,
    ) -> None:
        provider = _KerberosProviderForTokenTests(
            config={
                "realm": "EXAMPLE.COM",
                "kdc": "kdc.example.com",
                "service_principal": "HTTP/api.example.com@EXAMPLE.COM",
            }
        )
        result = provider.validate_token("opaque-kerberos-ticket")
        tm.fail(result)
        error = (result.error or "").lower()
        tm.that("kerberos" in error, eq=True)
        tm.that("validator" in error or "gssapi" in error, eq=True)

    def test_oauth2_validate_token_uses_authorization_server_introspection(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = FlextAuthOAuth2Provider({
            "client_id": "oauth-test-client",
            "client_secret": "oauth-test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "introspection_endpoint": "https://auth.example.com/introspect",
            "token_endpoint_auth_method": "client_secret_post",
        })
        call_count = {"count": 0}

        def _fake_introspect(token: str) -> r[dict[str, str | bool]]:
            call_count["count"] += 1
            tm.that(token, eq="opaque-oauth2-token")
            return r[dict[str, str | bool]].ok({
                "active": True,
                "sub": "oauth-user-123",
                "username": "oauth-user",
                "email": "oauth@example.com",
                "scope": "profile email",
            })

        monkeypatch.setattr(
            provider, "_introspect_token", _fake_introspect, raising=False
        )
        result = provider.validate_token("opaque-oauth2-token")
        tm.that(call_count["count"], eq=1)
        tm.ok(result)

    def test_oauth2_validate_token_fails_when_introspection_reports_inactive(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        provider = FlextAuthOAuth2Provider({
            "client_id": "oauth-test-client",
            "client_secret": "oauth-test-secret",
            "token_endpoint": "https://auth.example.com/token",
            "introspection_endpoint": "https://auth.example.com/introspect",
            "token_endpoint_auth_method": "client_secret_post",
        })

        def _inactive_introspect(_token: str) -> r[dict[str, str | bool]]:
            return r[dict[str, str | bool]].ok({"active": False})

        monkeypatch.setattr(
            provider, "_introspect_token", _inactive_introspect, raising=False
        )
        result = provider.validate_token("inactive-token")
        tm.fail(result, contains="inactive")

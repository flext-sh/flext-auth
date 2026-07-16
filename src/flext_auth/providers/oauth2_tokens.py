"""OAuth2 token operations."""

from __future__ import annotations

import secrets
from datetime import timedelta
from typing import override

from flext_auth import FlextAuthRfcProvider, c, m, p, r, t, u
from flext_auth.providers.oauth2_config import FlextAuthOAuth2Config
from flext_auth.providers.oauth2_introspection import FlextAuthOAuth2Introspection


class FlextAuthOAuth2Tokens(
    FlextAuthOAuth2Config,
    FlextAuthOAuth2Introspection,
    FlextAuthRfcProvider,
):
    """OAuth2 token operation owner."""

    use_pkce: bool

    @override
    def authenticate(
        self,
        credentials: t.JsonMapping,
    ) -> p.Result[p.Auth.Token]:
        """Authenticate using OAuth2 flows with delegation."""
        credential_payload: t.ConfigurationMapping = {
            k: v for k, v in credentials.items() if isinstance(v, t.PRIMITIVES_TYPES)
        }
        token_model = m.Auth.AuthToken(
            identity_id=str(
                credential_payload.get(c.Auth.KEY_USER_ID) or "oauth2_user",
            ),
            token=str(credential_payload.get("access_token") or ""),
            token_type="Bearer",
            expires_at=u.generate_datetime_utc() + timedelta(hours=1),
        )
        return r[p.Auth.Token].ok(token_model)

    @override
    def generate_token_for_user(
        self,
        user: p.Auth.AuthIdentity | t.JsonMapping,
        token_kind: str = "oauth2_access",
        token_type: str | None = None,
        expiry_minutes: int | None = None,
    ) -> p.Result[str]:
        """Generate OAuth2 token for user."""
        return super().generate_token_for_user(
            user=user,
            token_kind=token_kind,
            token_type=token_type,
            expiry_minutes=expiry_minutes,
        )

    def get_metadata(self) -> p.Auth.Providers.Metadata:
        """Get OAuth2 provider metadata using composition."""
        return m.Auth.Providers.Metadata(
            name="oauth2",
            version="1.0.0",
            capabilities=tuple(self.supports()),
            extras={
                "flows": [c.Auth.OAUTH2_FLOW_DEFAULT, "client_credentials"],
                "pkce_supported": self.use_pkce,
            },
        )

    @override
    def get_rfc_version(self) -> str:
        """Get the RFC version this provider implements.

        Returns:
            str: RFC version (e.g., "RFC 7617", "RFC 6749")

        """
        return "RFC 6749"

    @override
    def refresh(self, token: str | p.Auth.Token) -> p.Result[p.Auth.Token]:
        """Refresh OAuth2 token using composition."""
        token_text = self._extract_token_string(token)
        refresh_token_value = getattr(token, "refresh_token", "")
        has_refresh_token = isinstance(refresh_token_value, str) and bool(
            refresh_token_value,
        )
        refresh_source = refresh_token_value if has_refresh_token else token_text
        identity_id_result = (
            self._extract_identity_id(
                {
                    "identity_id": getattr(token, "identity_id", ""),
                    c.Auth.KEY_USER_ID: getattr(token, c.Auth.KEY_USER_ID, ""),
                },
            )
            if has_refresh_token
            else self._decode_token_claims(token_text).flat_map(
                self._extract_identity_id,
            )
        )
        identity_id = (
            identity_id_result.value if identity_id_result.success else "oauth2_user"
        )
        if not refresh_source:
            return r[p.Auth.Token].fail("No refresh token available")
        refreshed_model = m.Auth.AuthToken(
            identity_id=identity_id,
            token=f"access_token_{secrets.token_hex(16)}",
            token_type="Bearer",
            expires_at=u.generate_datetime_utc() + timedelta(seconds=3600),
            refresh_token=f"refresh_token_{secrets.token_hex(16)}",
        )
        return r[p.Auth.Token].ok(refreshed_model)

    @override
    def supports(self) -> set[str]:
        """Return OAuth2 provider capabilities using composition."""
        capabilities = {
            "oauth2",
            "authorization_code",
            "client_credentials",
            "token",
            "validate",
            "refresh",
        }
        if self.use_pkce:
            capabilities.add("pkce")
        if self.provider_config.authorization_endpoint:
            capabilities.add("authorization_url")
        return capabilities

    @override
    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate OAuth2 token using composition."""
        token_text = self._extract_token_string(token)
        return self.validate_token(token_text).fold(
            on_failure=lambda exc: r[bool].fail(
                exc or "OAuth2 token validation failed",
            ),
            on_success=lambda _: r[bool].ok(value=True),
        )

    def validate_token(self, token: str) -> p.Result[p.Auth.AuthIdentity]:
        """Validate OAuth2 token and return user."""
        introspection_endpoint_result = self._introspection_endpoint()
        if introspection_endpoint_result.success:
            introspection_result = self._introspect_token(token)
            if introspection_result.failure:
                return r[p.Auth.AuthIdentity].fail(
                    introspection_result.error
                    or "OAuth2 introspection token validation failed",
                )
            active_value = introspection_result.value.get("active")
            is_active = active_value if isinstance(active_value, bool) else False
            if not is_active:
                return r[p.Auth.AuthIdentity].fail("OAuth2 token is inactive")
            return r[p.Auth.AuthIdentity].from_validation(
                {
                    **introspection_result.value,
                    c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_OAUTH_CONTACT_DOMAIN,
                },
                m.Auth.AuthIdentity,
            )
        claims_result = self._decode_token_claims(token)
        if claims_result.failure:
            return r[p.Auth.AuthIdentity].fail(
                claims_result.error or "OAuth2 token validation failed",
            )
        return r[p.Auth.AuthIdentity].from_validation(
            {
                **claims_result.value,
                c.Auth.KEY_CONTACT_DOMAIN: c.Auth.DEFAULT_OAUTH_CONTACT_DOMAIN,
            },
            m.Auth.AuthIdentity,
        )


__all__: list[str] = ["FlextAuthOAuth2Tokens"]

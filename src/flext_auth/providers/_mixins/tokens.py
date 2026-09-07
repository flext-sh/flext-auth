"""Provider token operations."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timedelta

from flext_auth import c, m, p, r, t, u
from flext_auth.providers._mixins.codec import FlextAuthProviderCodecMixin


class FlextAuthProviderTokenMixin(FlextAuthProviderCodecMixin):
    _provider_config: t.ScalarMapping | None

    def generate_token(
        self,
        payload: t.JsonMapping,
        token_kind: str = "access",
        expiry_minutes: int | None = None,
    ) -> p.Result[str]:
        """Generate a token from the provided payload.

        Uses JWT encoding with the provider's configured secret_key and algorithm.

        Args:
            payload: Token payload claims.
            token_kind: Token type (access, refresh, id, bearer).
            expiry_minutes: Token expiration time in minutes (optional).

        Returns:
            r[str]: Encoded token string on success, error on failure.

        """
        settings = self._provider_config
        if not settings:
            return r[str].fail(
                "Provider configuration is required for token generation"
            )
        secret_key_value = settings.get("secret_key")
        if not isinstance(secret_key_value, str) or not secret_key_value:
            return r[str].fail("JWT secret_key not configured")
        algorithm_value = settings.get("algorithm")
        algorithm = (
            algorithm_value
            if isinstance(algorithm_value, str)
            else c.Auth.DEFAULT_JWT_ALGORITHM
        )
        expiry_config_value = settings.get("expiry_minutes")
        default_expiry = (
            expiry_config_value if isinstance(expiry_config_value, int) else 30
        )
        effective_expiry = (
            expiry_minutes if expiry_minutes is not None else default_expiry
        )
        now = u.generate_datetime_utc()
        claims: t.MutableJsonMapping = {
            k: int(v.timestamp()) if isinstance(v, datetime) else v
            for k, v in payload.items()
        }
        claims["iat"] = int(now.timestamp())
        claims["exp"] = int((now + timedelta(minutes=effective_expiry)).timestamp())
        claims["token_type"] = token_kind
        issuer_value = settings.get("issuer")
        if isinstance(issuer_value, str) and issuer_value:
            claims["iss"] = issuer_value
        audience_value = settings.get("audience")
        if isinstance(audience_value, str) and audience_value:
            claims["aud"] = audience_value
        return self._encode_token_payload(claims, secret_key_value, algorithm)

    def generate_token_for_user(
        self,
        user: m.Auth.AuthIdentity | t.JsonMapping,
        token_kind: str = "access",
        token_type: str | None = None,
        expiry_minutes: int | None = None,
    ) -> p.Result[str]:
        """Generate token for a user identity or claims mapping.

        Args:
            user: User identity model or claims dict.
            token_kind: Token type (access, refresh, id, bearer).
            token_type: Optional explicit token type.
            expiry_minutes: Token expiration time in minutes (optional).

        Returns:
            r[str]: Encoded token string on success, error on failure.

        """
        if isinstance(user, Mapping):
            payload = t.json_dict_adapter().validate_python(user)
        else:
            payload = user.model_dump()
        if "sub" not in payload and "unique_id" in payload:
            payload["sub"] = payload["unique_id"]
        effective_token_type = token_type if token_type is not None else token_kind
        payload["token_type"] = effective_token_type
        return self.generate_token(payload, token_kind, expiry_minutes)

    def refresh(self, token: str) -> p.Result[p.Auth.Token]:
        """Refresh authentication token.

        Decodes the existing token, extracts identity, and generates a new token.

        Args:
            token: Existing token to refresh.

        Returns:
            r[Token]: New token on success, error if refresh not supported or failed.

        """
        token_text = token
        claims_result = self._decode_token_claims(token_text)
        if claims_result.failure:
            return r[p.Auth.Token].from_failure(claims_result)
        claims = claims_result.value
        identity_result = self._extract_identity_id(claims)
        if identity_result.failure:
            return r[p.Auth.Token].from_failure(identity_result)
        identity_id = identity_result.value
        new_token_result = self.generate_token(claims, "access")
        if new_token_result.failure:
            return r[p.Auth.Token].from_failure(new_token_result)
        settings = self._provider_config
        expiry_config_value = settings.get("expiry_minutes") if settings else None
        default_expiry = (
            expiry_config_value if isinstance(expiry_config_value, int) else 30
        )
        refreshed = m.Auth.AuthToken(
            identity_id=identity_id,
            token=new_token_result.value,
            token_type="Bearer",
            expires_at=u.generate_datetime_utc() + timedelta(minutes=default_expiry),
        )
        return r[p.Auth.Token].ok(refreshed)


__all__: list[str] = ["FlextAuthProviderTokenMixin"]

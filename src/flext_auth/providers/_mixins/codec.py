"""Provider token codec helpers."""

from __future__ import annotations

from flext_auth import c, e, p, r, t, u


class FlextAuthProviderCodecMixin:
    _provider_config: t.ScalarMapping | None

    def _decode_token_claims(
        self,
        token: str,
    ) -> p.Result[t.Auth.TokensClaimMap]:
        """Decode JWT token and return claims payload.

        Args:
            token: JWT token string to decode.

        Returns:
            r[t.JsonMapping]: Decoded claims on success, error on failure.

        """
        settings = self._provider_config
        if not settings:
            return r[t.Auth.TokensClaimMap].fail(
                "Provider configuration required for token decoding",
            )
        decoded: p.Result[t.Auth.TokensClaimMap] = u.Auth.decode_token(
            token,
            settings,
        )
        return decoded

    @staticmethod
    def _encode_token_payload(
        payload: t.JsonMapping,
        secret: str,
        algorithm: str,
    ) -> p.Result[str]:
        """Encode token payload using JWT with canonical result flow."""
        normalized_payload = t.json_dict_adapter().validate_python(payload)
        encoded: p.Result[str] = u.Auth.encode_token(
            normalized_payload,
            secret,
            algorithm,
        )
        return encoded

    def _extract_identity_id(
        self,
        claims: t.JsonMapping,
    ) -> p.Result[str]:
        """Extract identity ID from token claims.

        Checks common identity fields (sub, identity_id, user_id, username)
        in priority order and returns the first valid string.

        Args:
            claims: Token claims mapping.

        Returns:
            r[str]: Identity ID on success, error if no identity field found.

        """
        for field in c.Auth.TOKEN_IDENTITY_KEYS:
            value = claims.get(field)
            if isinstance(value, str) and value:
                return r[str].ok(value)
        return r[str].fail(
            "No identity field found in token claims "
            f"(checked: {', '.join(c.Auth.TOKEN_IDENTITY_KEYS)})",
        )

    def _extract_token_string(self, token: str | p.Auth.Token) -> str:
        """Extract token string from token or Token t.JsonValue.

        Args:
        token: Token as string or Token t.JsonValue

        Returns:
        str: Token string

        Raises:
        ValueError: If token cannot be extracted

        """
        token_value = token.token if isinstance(token, p.Auth.Token) else token
        token_text = token_value
        if token_text:
            return token_text
        error_msg = f"Invalid token type: expected str or Token, got {type(token)}"
        raise e.ValidationError(error_msg, field="token", value=str(type(token)))


__all__: list[str] = ["FlextAuthProviderCodecMixin"]

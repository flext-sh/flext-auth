"""Provider token codec helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping

from flext_auth import c, p, r, t, u


class FlextAuthProviderCodec:
    """JWT encode/decode helpers shared by token-based providers."""

    _provider_config: Mapping[str, t.Scalar] | None

    def _decode_token_claims(self, token: str) -> p.Result[t.Auth.TokensClaimMap]:
        """Decode JWT token and return claims payload.

        Args:
            token: JWT token string to decode.

        Returns:
            The decoded claims mapping; failure when provider
            configuration is missing or decoding fails.

        """
        settings = self._provider_config
        if not settings:
            return r[t.Auth.TokensClaimMap].fail(
                "Provider configuration required for token decoding",
            )
        decoded: p.Result[t.Auth.TokensClaimMap] = u.Auth.decode_token(token, settings)
        return decoded

    @staticmethod
    def _encode_token_payload(
        payload: t.JsonMapping,
        secret: str,
        algorithm: str,
    ) -> p.Result[str]:
        """Encode token payload using JWT with canonical result flow.

        Args:
            payload: Token payload claims to encode.
            secret: Secret key used for signing.
            algorithm: JWT signing algorithm.

        Returns:
            The encoded token string; failure on encoding errors.

        """
        normalized_payload = u.json_dict_adapter().validate_python(payload)
        encoded: p.Result[str] = u.Auth.encode_token(
            normalized_payload,
            secret,
            algorithm,
        )
        return encoded

    @staticmethod
    def _extract_identity_id(claims: t.JsonMapping) -> p.Result[str]:
        """Extract identity ID from token claims.

        Checks common identity fields (sub, identity_id, user_id, username)
        in priority order and returns the first valid string.

        Args:
            claims: Token claims mapping.

        Returns:
            The identity ID from the first matching claim; failure when no
            identity field is found.

        """
        for field in c.Auth.TOKEN_IDENTITY_KEYS:
            value = claims.get(field)
            if isinstance(value, str) and value:
                return r[str].ok(value)
        return r[str].fail(
            "No identity field found in token claims "
            f"(checked: {', '.join(c.Auth.TOKEN_IDENTITY_KEYS)})",
        )

    @staticmethod
    def _extract_token_string(token: str | p.Auth.Token) -> str:
        """Extract the token string from a token value or token entity.

        Coercion is total: an empty token flows onward so the domain
        validators own the failure through the result railway.

        Args:
            token: Token as plain string or token entity.

        Returns:
            The token string carried by the input.

        """
        return token.token if isinstance(token, p.Auth.Token) else token


__all__: list[str] = ["FlextAuthProviderCodec"]

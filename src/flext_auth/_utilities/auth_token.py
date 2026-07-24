"""Authentication token encode/decode utilities."""

from __future__ import annotations

import jwt

from flext_api import r
from flext_auth import c, m, p, t


class FlextAuthUtilitiesAuthToken:
    @staticmethod
    def decode_token(
        token: str,
        config: p.Auth.ProviderConfig | t.ScalarMapping,
        *,
        verify: bool = True,
    ) -> p.Result[t.Auth.TokensClaimMap]:
        """Decode a JWT token.

        Args:
            token: JWT token to decode
            config: Provider configuration with JWT secret and claims settings
            verify: Whether to verify signature

        Returns:
            r with decoded payload or error

        """
        try:
            provider_config = (
                config
                if isinstance(config, m.Auth.ProviderConfig)
                else m.Auth.ProviderConfig.model_validate({
                    c.Auth.KEY_NAME: c.Auth.ProviderTypes.JWT.value,
                    "type": c.Auth.ProviderTypes.JWT.value,
                    **config,
                })
            )
            if not provider_config.secret_key:
                return r[t.Auth.TokensClaimMap].fail("JWT secret_key not configured")
            algorithm = provider_config.algorithm or c.Auth.JWT_DEFAULT_ALGORITHM
            payload = jwt.decode(
                token,
                provider_config.secret_key,
                algorithms=[algorithm],
                options={"verify_signature": verify},
                audience=provider_config.audience,
            )
            typed_payload = t.json_dict_adapter().validate_python(payload)
            return r[t.Auth.TokensClaimMap].ok(typed_payload)
        except jwt.InvalidTokenError as exc:
            return r[t.Auth.TokensClaimMap].fail(f"Invalid token: {exc}")
        except c.ValidationError as exc:
            return r[t.Auth.TokensClaimMap].fail_op(
                "Decoded token payload validation", exc
            )
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[t.Auth.TokensClaimMap].fail_op("Decoding", exc)

    @staticmethod
    def encode_token(
        payload: t.Auth.TokensClaimMap,
        secret: str,
        algorithm: str = c.Auth.JWT_DEFAULT_ALGORITHM,
    ) -> p.Result[str]:
        """Encode a JWT token.

        Args:
        payload: Token payload
        secret: Secret key for signing
        algorithm: JWT algorithm

        Returns:
        r with encoded token or error

        """
        try:
            encoded = jwt.encode(
                t.json_dict_adapter().validate_python(payload),
                secret,
                algorithm=algorithm,
            )
            return r[str].ok(encoded)
        except c.EXC_BROAD_IO_TYPE as exc:
            return r[str].fail_op("Encoding", exc)


__all__: list[str] = ["FlextAuthUtilitiesAuthToken"]

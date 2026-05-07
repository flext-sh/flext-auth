"""FLEXT Auth Provider Mixin - Common functionality for authentication providers.

This module provides common utility methods for authentication providers
to reduce code duplication while maintaining the single class per module rule.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    Mapping,
)
from datetime import UTC, datetime, timedelta

from flext_auth import c, e, m, p, r, t, u


class FlextAuthProviderMixin:
    """Mixin providing common functionality for authentication providers.

    Provides default implementations for FlextAuthBaseProvider protocol methods
    and shared utility methods used by concrete providers. Stores provider
    configuration and supplies JWT-based token operations.

    Example:
    >>> class FlextAuthJwtProvider(FlextAuthBaseProvider, FlextAuthProviderMixin):
    ...     pass

    """

    _provider_config: t.ScalarMapping | None

    def __init__(self, settings: t.ScalarMapping | None = None) -> None:
        """Initialize provider mixin with optional configuration.

        Args:
            settings: Provider configuration mapping with scalar values.

        """
        super().__init__()
        self._provider_config = settings

    @property
    def settings(self) -> t.ScalarMapping | None:
        """Get provider configuration."""
        return self._provider_config

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
        now = datetime.now(UTC)
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
            return r[p.Auth.Token].fail(
                claims_result.error or "Token decode failed during refresh"
            )
        claims = claims_result.value
        identity_result = self._extract_identity_id(claims)
        if identity_result.failure:
            return r[p.Auth.Token].fail(
                identity_result.error or "Identity extraction failed during refresh"
            )
        identity_id = identity_result.value
        new_token_result = self.generate_token(claims, "access")
        if new_token_result.failure:
            return r[p.Auth.Token].fail(
                new_token_result.error or "Token generation failed during refresh"
            )
        settings = self._provider_config
        expiry_config_value = settings.get("expiry_minutes") if settings else None
        default_expiry = (
            expiry_config_value if isinstance(expiry_config_value, int) else 30
        )
        refreshed = m.Auth.AuthToken(
            identity_id=identity_id,
            token=new_token_result.value,
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(minutes=default_expiry),
        )
        return r[p.Auth.Token].ok(refreshed)

    def revoke(self, token: str) -> p.Result[bool]:
        """Revoke authentication token.

        Default implementation returns an error indicating revocation is
        not supported. Providers that support revocation should override.

        Args:
            token: Token to revoke.

        Returns:
            r[bool]: True on success, error if revocation not supported.

        """
        _ = token
        return r[bool].fail("Token revocation not supported by this provider")

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        This is a default implementation that returns an empty set.
        Providers should override this method to declare their capabilities.
        """
        return set()

    def _check_capability_supported(self, capability: str) -> p.Result[bool]:
        """Check if a capability is supported by this provider.

        Args:
            capability: Capability to check

        Returns:
            r[bool]: True if supported, False if not, error message on failure

        Example:
            >>> result = self._check_capability_supported("refresh")
            >>> if result.failure or not result.value:
            ...     return r[AuthToken].fail("Refresh not supported")

        """
        if capability not in self.supports():
            return r[bool].fail(
                f"Provider does not support '{capability}' capability. Supported capabilities: {', '.join(sorted(self.supports()))}",
            )
        return r[bool].ok(value=True)

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
                "Provider configuration required for token decoding"
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
            normalized_payload, secret, algorithm
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
            f"(checked: {', '.join(c.Auth.TOKEN_IDENTITY_KEYS)})"
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

    def _get_capability_metadata(self) -> t.JsonMapping:
        """Get metadata about provider capabilities.

        Returns:
            t.JsonMapping: Metadata including supported capabilities

        Example:
            >>> metadata = provider._get_capability_metadata()
            >>> print(f"Capabilities: {', '.join(metadata['capabilities'])}")

        """
        capabilities: t.JsonValueList = list(self.supports())
        metadata: t.JsonMapping = {
            "capabilities": capabilities,
            "provider_type": self.__class__.__name__,
        }
        return metadata

    def _validate_credentials_dict(
        self,
        credentials: t.JsonMapping,
        required_fields: t.StrSequence,
    ) -> p.Result[bool]:
        """Validate that credentials contain required fields.

        Args:
        credentials: Credentials dictionary to validate
        required_fields: List of required field names

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        missing_fields = u.filter(
            required_fields,
            lambda field: field not in credentials,
        )
        if missing_fields:
            error_msg = f"Missing required fields: {', '.join(missing_fields)}"
            return r[bool].fail(error_msg)
        return r[bool].ok(value=True)

    def _validate_token_string(self, token: str) -> p.Result[bool]:
        """Validate token string format.

        Args:
        token: Token string to validate

        Returns:
        r[bool]: True if valid, False if invalid, error message on failure

        """
        if not token:
            return r[bool].fail("Token must be a non-empty string")
        if not token.strip():
            return r[bool].fail("Token cannot be empty or whitespace only")
        return r[bool].ok(value=True)


__all__: t.MutableSequenceOf[str] = ["FlextAuthProviderMixin"]

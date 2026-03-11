"""Base authentication provider protocol for FLEXT Auth.

This module defines the abstract base class that all authentication providers
must inherit from, providing a consistent interface for authentication operations
such as login, token refresh, validation, and revocation.

The protocol ensures railway-oriented programming patterns with FlextResult returns
and supports various authentication methods (JWT, API keys, OAuth, etc.).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

import jwt
from flext_core import r, t, u

from flext_auth import m, p


@runtime_checkable
class FlextAuthBaseProvider(Protocol):
    """Base protocol for all authentication providers.

    All authentication providers must implement this interface to ensure
    consistent behavior across different authentication technologies (JWT,
    OAuth2, SAML, etc.).
    """

    _provider_config: Mapping[str, t.Primitives] | None

    def __init__(self, config: Mapping[str, t.Primitives] | None = None) -> None:
        """Initialize provider with optional configuration.

        Args:
            config: Provider configuration (optional, provider-specific)

        """
        self._provider_config = config

    @property
    def config(self) -> Mapping[str, t.Primitives] | None:
        """Get provider configuration."""
        return self._provider_config

    @staticmethod
    def _extract_expiration_datetime(
        payload: Mapping[str, t.ContainerValue],
    ) -> r[datetime]:
        exp_value = payload.get("exp")
        match exp_value:
            case int() as exp_ts if exp_ts > 0:
                timestamp = float(exp_ts)
            case float() as exp_ts if exp_ts > 0:
                timestamp = exp_ts
            case _:
                return r[datetime].fail("Token payload must include a valid exp claim")
        return u.try_(
            lambda: datetime.fromtimestamp(timestamp, UTC),
            catch=(ValueError, OSError, OverflowError, TypeError, RuntimeError),
        ).map_error(lambda exc: f"Token exp claim conversion failed: {exc}")

    @staticmethod
    def _extract_identity_id(payload: Mapping[str, t.ContainerValue]) -> r[str]:
        for key in ("identity_id", "unique_id", "id", "user_id", "sub", "name"):
            value = payload.get(key)
            if isinstance(value, str) and value:
                return r[str].ok(value)
        return r[str].fail("User payload must include identity identifier")

    @staticmethod
    def _normalize_claim_value(value: t.ContainerValue) -> t.ContainerValue | None:
        if value is None:
            return None
        if isinstance(value, (str, int, float, bool)):
            return value
        if isinstance(value, datetime):
            return value.isoformat()
        if isinstance(value, (list, tuple)):
            normalized_items: list[t.ContainerValue] = []
            for item in value:
                normalized_item = FlextAuthBaseProvider._normalize_claim_value(item)
                if normalized_item is not None:
                    normalized_items.append(normalized_item)
            return normalized_items
        if isinstance(value, Mapping):
            normalized_mapping: dict[str, t.ContainerValue] = {}
            for key, item in value.items():
                normalized_item = FlextAuthBaseProvider._normalize_claim_value(item)
                if normalized_item is not None:
                    normalized_mapping[key] = normalized_item
            return normalized_mapping
        return value

    def authenticate(
        self, credentials: m.Auth.CredentialValidation
    ) -> r[p.Auth.TokenProtocol]:
        """Authenticate user with provided credentials.

        This is the primary authentication method. It should validate the
        provided credentials and, if valid, return an authentication token.

        Args:
            credentials: Dictionary containing authentication credentials.
                        The exact structure depends on the provider type.

        Returns:
            r[p.Auth.TokenProtocol]: Authentication token on success,
                                   error message on failure

        """
        ...

    def generate_token(
        self,
        payload: Mapping[str, t.ContainerValue],
        token_type: str = "access",
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate a signed JWT token from the provided payload."""
        settings_result = self._token_settings()
        if settings_result.is_failure:
            return r[str].fail(settings_result.error or "Token settings are invalid")
        identity_result = self._extract_identity_id(payload)
        if identity_result.is_failure:
            return r[str].fail(
                identity_result.error or "Identity identifier is required"
            )
        secret_key, algorithm_name, issuer_name, audience_name, default_expiry = (
            settings_result.value
        )
        effective_expiry: int
        match expiry_minutes:
            case None:
                effective_expiry = default_expiry
            case int() as custom_expiry if custom_expiry > 0:
                effective_expiry = custom_expiry
            case _:
                return r[str].fail("expiry_minutes must be a positive integer")
        identity_id = identity_result.value
        name_value = payload.get("name")
        name = name_value if isinstance(name_value, str) and name_value else identity_id
        contact_value = payload.get("contact")
        if isinstance(contact_value, str) and contact_value:
            contact = contact_value
        else:
            email_value = payload.get("email")
            contact = (
                email_value
                if isinstance(email_value, str) and email_value
                else f"{identity_id}@local"
            )
        roles_value = payload.get("roles")
        user_roles: list[str]
        if isinstance(roles_value, list):
            user_roles = [
                role for role in roles_value if isinstance(role, str) and role
            ]
        else:
            user_roles = []
        now = datetime.now(UTC)
        claims: dict[str, t.ContainerValue] = {}
        reserved_claims = {
            "sub",
            "identity_id",
            "name",
            "email",
            "roles",
            "token_type",
            "iat",
            "exp",
            "iss",
            "aud",
        }
        for key, value in payload.items():
            if key in reserved_claims:
                continue
            normalized_value = self._normalize_claim_value(value)
            if normalized_value is not None:
                claims[key] = normalized_value
        claims.update({
            "sub": identity_id,
            "identity_id": identity_id,
            "name": name,
            "email": contact,
            "roles": user_roles,
            "token_type": token_type or "access",
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(minutes=effective_expiry)).timestamp()),
            "iss": issuer_name,
            "aud": audience_name,
        })

        def _encode_token() -> str:
            encoded_token = jwt.encode(claims, secret_key, algorithm=algorithm_name)
            if isinstance(encoded_token, str):
                return encoded_token
            return str(encoded_token)

        return u.try_(
            _encode_token,
            catch=(
                jwt.PyJWTError,
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ),
        ).map_error(lambda exc: f"Token generation failed: {exc}")

    def generate_token_for_user(
        self,
        user: m.Auth.AuthIdentity | t.ConfigurationMapping,
        token_type: str = "access",
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Generate authentication token for a user.

        Create a new token for an authenticated user (post-authentication token generation).
        This is distinct from authenticate() which validates credentials.

        Args:
            user: User/identity dictionary with user data
            token_type: Token type (access, refresh, id, bearer)
            expiry_minutes: Token expiration time in minutes (optional)

        Returns:
            r[str]: Encoded token string on success, error on failure

        """
        settings_result = self._token_settings()
        if settings_result.is_failure:
            return r[str].fail(settings_result.error or "Token settings are invalid")
        payload_result = self._normalize_identity_payload(user)
        if payload_result.is_failure:
            return r[str].fail(payload_result.error or "Invalid user payload")
        return self.generate_token(
            payload=payload_result.value,
            token_type=token_type,
            expiry_minutes=expiry_minutes,
        )

    def refresh(self, token: str) -> r[p.Auth.TokenProtocol]:
        """Refresh authentication token.

        Generate a new token based on an existing valid token. This operation
        is optional and should return an error if the provider doesn't support
        token refresh.

        Args:
            token: Existing token to refresh

        Returns:
            r[p.Auth.TokenProtocol]: New token on success,
                                   error if refresh not supported or failed

        """
        claims_result = self._decode_token_claims(token)
        if claims_result.is_failure:
            return r[p.Auth.TokenProtocol].fail(
                claims_result.error or "Source token validation failed"
            )
        source_claims = claims_result.value
        identity_result = self._extract_identity_id(source_claims)
        if identity_result.is_failure:
            return r[p.Auth.TokenProtocol].fail(
                identity_result.error or "Token subject is missing"
            )
        refresh_type_value = source_claims.get("token_type")
        refresh_type = (
            refresh_type_value
            if isinstance(refresh_type_value, str) and refresh_type_value
            else "access"
        )
        generation_result = self.generate_token(
            payload=source_claims, token_type=refresh_type, expiry_minutes=None
        )
        if generation_result.is_failure:
            return r[p.Auth.TokenProtocol].fail(
                generation_result.error or "Token refresh generation failed"
            )
        refreshed_claims_result = self._decode_token_claims(generation_result.value)
        if refreshed_claims_result.is_failure:
            return r[p.Auth.TokenProtocol].fail(
                refreshed_claims_result.error or "Refreshed token validation failed"
            )
        expires_result = self._extract_expiration_datetime(
            refreshed_claims_result.value
        )
        if expires_result.is_failure:
            return r[p.Auth.TokenProtocol].fail(
                expires_result.error or "Refreshed token exp claim is invalid"
            )
        refresh_token_value = source_claims.get("refresh_token")
        refresh_token = (
            refresh_token_value
            if isinstance(refresh_token_value, str) and refresh_token_value
            else token
        )

        def _build_refreshed_token() -> p.Auth.TokenProtocol:
            return m.Auth.AuthToken(
                identity_id=identity_result.value,
                token=generation_result.value,
                token_type=refresh_type,
                expires_at=expires_result.value,
                is_revoked=False,
                refresh_token=refresh_token,
            )

        return u.try_(
            _build_refreshed_token,
            catch=(ValueError, TypeError),
        ).map_error(lambda exc: f"Refreshed token model mapping failed: {exc}")

    def revoke(self, _token: str) -> r[bool]:
        """Revoke authentication token.

        Invalidate the provided token, preventing further use. This operation
        is optional and should return an error if the provider doesn't support
        token revocation.

        Args:
            _token: Token to revoke

        Returns:
            r[bool]: True if revoked successfully,
                   False if revocation not supported or failed,
                   error message on failure

        """
        return r[bool].fail("Token revocation not supported")

    def supports(self) -> set[str]:
        """Return set of capabilities supported by this provider.

        Capabilities help consumers understand what operations are available
        for this provider. This allows graceful degradation when using providers
        with different feature sets.

        Returns:
            set[str]: Set of supported operations

        """
        return {"authenticate", "validate"}

    def validate(self, token: str) -> r[bool]:
        """Validate authentication token.

        Check if the provided token is valid and has not expired.

        Args:
            token: Token to validate

        Returns:
            r[bool]: True if valid, False if invalid, error on failure

        """
        ...

    def _decode_token_claims(self, token: str) -> r[Mapping[str, t.ContainerValue]]:
        if not token.strip():
            return r[t.ConfigurationMapping].fail("Token must be a non-empty string")
        settings_result = self._token_settings()
        if settings_result.is_failure:
            return r[t.ConfigurationMapping].fail(
                settings_result.error or "Token settings are invalid"
            )
        secret_key, algorithm_name, issuer_name, audience_name, _default_expiry = (
            settings_result.value
        )
        try:
            decoded_payload = jwt.decode(
                token,
                secret_key,
                algorithms=[algorithm_name],
                audience=audience_name,
                issuer=issuer_name,
                options={"verify_iat": True, "verify_exp": True},
            )
        except jwt.ExpiredSignatureError:
            return r[t.ConfigurationMapping].fail("Token has expired")
        except jwt.InvalidTokenError as exc:
            return r[t.ConfigurationMapping].fail(f"Invalid token: {exc}")
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as exc:
            return r[t.ConfigurationMapping].fail(f"Token validation failed: {exc}")
        return r[t.ConfigurationMapping].ok(decoded_payload)

    def _normalize_identity_payload(
        self, user: m.Auth.AuthIdentity | t.ConfigurationMapping
    ) -> r[Mapping[str, t.ContainerValue]]:
        if isinstance(user, Mapping):
            return r[t.ConfigurationMapping].ok(user)
        # At this point, user is narrowed to m.Auth.AuthIdentity by type system
        return r[t.ConfigurationMapping].ok(
            user.model_dump(exclude={"credential_hash", "token", "refresh_token"})
        )

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider"

    def _token_settings(self) -> r[tuple[str, str, str, str, int]]:
        config = self.config
        if config is None:
            return r[tuple[str, str, str, str, int]].fail(
                "Provider configuration is required for token operations"
            )
        secret_value = config.get("secret_key")
        match secret_value:
            case str() as secret if secret:
                secret_key = secret
            case _:
                return r[tuple[str, str, str, str, int]].fail(
                    "Token secret_key is not configured"
                )
        algorithm_value = config.get("algorithm", "HS256")
        match algorithm_value:
            case str() as algorithm if algorithm:
                algorithm_name = algorithm
            case _:
                return r[tuple[str, str, str, str, int]].fail(
                    "Token algorithm is invalid"
                )
        issuer_value = config.get("issuer", "flext-auth")
        match issuer_value:
            case str() as issuer if issuer:
                issuer_name = issuer
            case _:
                issuer_name = "flext-auth"
        audience_value = config.get("audience", "flext-auth")
        match audience_value:
            case str() as audience if audience:
                audience_name = audience
            case _:
                audience_name = "flext-auth"
        expiry_value = config.get("expiry_minutes")
        match expiry_value:
            case int() as expiry if expiry > 0:
                default_expiry = expiry
            case _:
                token_expiry_value = config.get("token_expiry_minutes")
                match token_expiry_value:
                    case int() as token_expiry if token_expiry > 0:
                        default_expiry = token_expiry
                    case _:
                        default_expiry = 60
        return r[tuple[str, str, str, str, int]].ok((
            secret_key,
            algorithm_name,
            issuer_name,
            audience_name,
            default_expiry,
        ))


__all__ = ["FlextAuthBaseProvider"]

"""Authentication provider protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_auth import c, t

if TYPE_CHECKING:
    from flext_api import p

    from flext_auth._protocols import FlextAuthProtocolsAuthSession


class FlextAuthProtocolsAuthProvider:
    """Protocol namespace for provider registries and providers."""

    @runtime_checkable
    class ProviderRegistry(Protocol):
        """Registry operations consumed by provider orchestration."""

        def get(
            self,
            data: str,
        ) -> p.Result[FlextAuthProtocolsAuthProvider.FlextAuthBaseProvider]:
            """Resolve the registered provider by name.

            Args:
                data: Registered provider name.

            Returns:
                The provider instance; failure when unregistered.

            """
            ...

        def list_providers(self) -> t.StrSequence:
            """Return registered provider names.

            Returns:
                Names of all registered providers.

            """
            ...

        def register_provider(
            self,
            name: str,
            provider: FlextAuthProtocolsAuthProvider.FlextAuthBaseProvider,
            *,
            configuration: t.ConfigurationMapping | None = None,
        ) -> p.Result[bool]:
            """Register the provided implementation under its name.

            Args:
                name: Unique registration name for the provider.
                provider: Provider instance to register.
                configuration: Optional provider configuration mapping.

            Returns:
                Success when the provider is registered.

            """
            ...

    @runtime_checkable
    class FlextAuthBaseProvider(Protocol):
        """Base protocol for all authentication providers.

        All authentication providers must implement this interface to ensure
        consistent behavior across different authentication technologies (JWT,
        OAuth2, SAML, etc.).
        """

        def __init__(self, settings: t.ScalarMapping | None = None) -> None:
            """Initialize provider with optional configuration.

            Args:
                settings: Optional scalar provider settings mapping.

            """
            ...

        @property
        def settings(self) -> t.ScalarMapping | None:
            """Provider configuration mapping."""
            ...

        def authenticate(
            self,
            credentials: t.JsonMapping,
        ) -> p.Result[FlextAuthProtocolsAuthSession.Token]:
            """Authenticate user with provided credentials.

            This is the primary authentication method. It should validate the
            provided credentials and, if valid, return an authentication token.

            Args:
                credentials: Dictionary containing authentication credentials.
                            The exact structure depends on the provider type.

            Returns:
                The authentication token on success; failure with an error
                message otherwise.

            """
            ...

        def generate_token(
            self,
            payload: t.JsonMapping,
            token_kind: str = c.Auth.TokenTypes.ACCESS.value,
            expiry_minutes: int | None = None,
        ) -> p.Result[str]:
            """Generate a signed token from the provided payload.

            Args:
                payload: Token payload claims to sign.
                token_kind: Token type (access, refresh, id, bearer).
                expiry_minutes: Token expiration time in minutes (optional).

            Returns:
                The encoded token string; failure on signing errors.

            """
            ...

        def generate_token_for_user(
            self,
            user: t.JsonMapping,
            token_kind: str = c.Auth.TokenTypes.ACCESS.value,
            token_type: str | None = None,
            expiry_minutes: int | None = None,
        ) -> p.Result[str]:
            """Generate token for a user identity or claims mapping.

            Args:
                user: User claims dict.
                token_kind: Token type (access, refresh, id, bearer).
                token_type: Explicit token type override if requested.
                expiry_minutes: Token expiration time in minutes (optional).

            Returns:
                The encoded token string; failure on encoding errors.

            """
            ...

        def refresh(self, token: str) -> p.Result[FlextAuthProtocolsAuthSession.Token]:
            """Refresh authentication token.

            Generate a new token based on an existing valid token. This operation
            is optional and should return an error if the provider doesn't support
            token refresh.

            Args:
                token: Existing token to refresh.

            Returns:
                The new token on success; failure when refresh is
                unsupported or fails.

            """
            ...

        def revoke(self, token: str) -> p.Result[bool]:
            """Revoke authentication token.

            Invalidate the provided token, preventing further use. This operation
            is optional and should return an error if the provider doesn't support
            token revocation.

            Args:
                token: Token to revoke.

            Returns:
                Whether the token was revoked successfully.

            """
            ...

        def supports(self) -> set[str]:
            """Return set of capabilities supported by this provider.

            Capabilities help consumers understand what operations are available
            for this provider. This allows graceful degradation when using providers
            with different feature sets.

            Returns:
                Set of supported operations.

            """
            ...

        def validate(self, token: str) -> p.Result[bool]:
            """Validate authentication token.

            Check if the provided token is valid and has not expired.

            Args:
                token: Token to validate.

            Returns:
                Whether the token is valid.

            """
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthProvider"]

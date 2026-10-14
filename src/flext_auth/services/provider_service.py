"""FLEXT Auth provider service.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuthRegistry, FlextAuthSettings, c, m, p, s, t
from flext_auth.services import FlextAuthProviderBuiltinRegistration


class FlextAuthProviderService(s, FlextAuthProviderBuiltinRegistration):
    """Provider service using flext-core patterns and railway-oriented programming."""

    def __init__(
        self,
        *,
        settings: p.Settings | None = None,
        registry: p.Auth.ProviderRegistry | None = None,
    ) -> None:
        """Flexible initialization with automatic provider registration.

        Args:
            settings: Optional settings payload overriding the global auth
                settings.
            registry: Optional provider registry; defaults to a fresh auth
                registry with builtin providers registered.

        """
        super().__init__()
        self._auth_config = (
            FlextAuthSettings.model_validate(settings.model_dump())
            if settings is not None
            else FlextAuthSettings.fetch_global()
        )
        self._providers = registry if registry is not None else FlextAuthRegistry()
        self._register_builtin_providers()

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> p.Result[p.Auth.Token]:
        """Railway-oriented user authentication with provider selection.

        Args:
            username: Account name to authenticate.
            password: Plain credential for the account.
            provider: Registered provider name handling the credentials.

        Returns:
            The token issued for the authenticated user; failure when the
            provider rejects the credentials.

        """
        credentials = m.Auth.CredentialValidation(username=username, password=password)
        return self._providers.get(provider).flat_map(
            lambda auth_provider: auth_provider.authenticate(
                credentials.model_dump(exclude_none=True),
            ),
        )

    def generate_token_for_user(
        self,
        user: m.Auth.AuthIdentity,
        provider: str = "jwt",
        token_kind: str = c.Auth.TokenTypes.ACCESS.value,
        token_type: str | None = None,
        expiry_minutes: int | None = None,
    ) -> p.Result[str]:
        """Railway-oriented token generation with direct provider access.

        Args:
            user: Identity to mint the token for.
            provider: Registered provider generating the token.
            token_kind: Token kind, such as access or refresh.
            token_type: Optional explicit token type overriding the kind.
            expiry_minutes: Optional custom lifetime in minutes.

        Returns:
            The signed token string; failure when the provider rejects the
            request.

        """
        effective_token_type = token_type if token_type is not None else token_kind
        return self._providers.get(provider).flat_map(
            lambda p: p.generate_token_for_user(
                user.model_dump(mode="json"),
                token_kind,
                effective_token_type,
                expiry_minutes,
            ),
        )

    def fetch_jwt_provider(self) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Fetch the registered JWT provider through the public provider protocol.

        Returns:
            The registered JWT provider instance; failure when absent.

        """
        return self._providers.get("jwt")

    def fetch_provider(self, name: str) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Fetch registered provider.

        Args:
            name: Registered provider name.

        Returns:
            The provider instance; failure when unregistered.

        """
        return self._providers.get(name)

    def list_providers(self) -> t.StrSequence:
        """List registered provider names.

        Returns:
            Names of all registered providers.

        """
        return self._providers.list_providers()

    def register_provider(
        self,
        name: str,
        provider: p.Auth.FlextAuthBaseProvider,
    ) -> p.Result[bool]:
        """Register custom provider.

        Args:
            name: Unique registration name for the provider.
            provider: Provider instance to register.

        Returns:
            Success when the provider is registered.

        """
        return self._providers.register_provider(name, provider)

    def validate_token(self, token: str, provider: str = "jwt") -> p.Result[bool]:
        """Railway-oriented token validation with direct provider access.

        Args:
            token: Token string to validate.
            provider: Registered provider validating the token.

        Returns:
            Whether the provider accepts the token.

        """
        return self._providers.get(provider).flat_map(
            lambda auth_provider: auth_provider.validate(token),
        )


__all__: t.MutableSequenceOf[str] = ["FlextAuthProviderService"]

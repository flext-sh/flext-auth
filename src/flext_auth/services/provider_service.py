"""FLEXT Auth provider service."""

from __future__ import annotations

from typing import override

from flext_api import r

from flext_auth import FlextAuthRegistry, FlextAuthSettings, c, m, p, s, t
from flext_auth.services._provider_builtin import FlextAuthProviderBuiltinRegistration


class FlextAuthProviderService(s, FlextAuthProviderBuiltinRegistration):
    """Provider service using flext-core patterns and railway-oriented programming."""

    def __init__(
        self,
        *,
        settings: FlextAuthSettings | None = None,
        registry: FlextAuthRegistry | None = None,
    ) -> None:
        """Flexible initialization with automatic provider registration."""
        super().__init__()
        self._auth_config = settings if settings is not None else FlextAuthSettings()
        self._providers = registry if registry is not None else FlextAuthRegistry()
        self._register_builtin_providers()

    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> p.Result[p.Auth.Token]:
        """Railway-oriented user authentication with provider selection."""
        credentials = m.Auth.CredentialValidation(username=username, password=password)
        return self._providers.get(provider).flat_map(
            lambda auth_provider: auth_provider.authenticate(
                credentials.model_dump(exclude_none=True)
            ),
        )

    @override
    def execute(self) -> p.Result[p.Base]:
        """Railway-oriented execute with focused service pattern."""
        return r[p.Base].fail(
            "Use specific provider methods: get_provider, authenticate_user, etc.",
        )

    def generate_token_for_user(
        self,
        user: m.Auth.AuthIdentity,
        provider: str = "jwt",
        token_kind: str = c.Auth.TokenTypes.ACCESS.value,
        token_type: str | None = None,
        expiry_minutes: int | None = None,
    ) -> p.Result[str]:
        """Railway-oriented token generation with direct provider access."""
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
        """Fetch the registered JWT provider through the public provider protocol."""
        return self._providers.get("jwt")

    def fetch_provider(self, name: str) -> p.Result[p.Auth.FlextAuthBaseProvider]:
        """Fetch registered provider."""
        return self._providers.get(name)

    def list_providers(self) -> t.StrSequence:
        """List registered provider names."""
        return self._providers.list_providers()

    def register_provider(
        self,
        name: str,
        provider: p.Auth.FlextAuthBaseProvider,
    ) -> p.Result[bool]:
        """Register custom provider.

        Returns:
            r[bool]: True if registered successfully, False if failed, error on failure

        """
        return self._providers.register_provider(name, provider).map(lambda _: True)

    def validate_token(self, token: str, provider: str = "jwt") -> p.Result[bool]:
        """Railway-oriented token validation with direct provider access."""
        return self._providers.get(provider).flat_map(lambda p: p.validate(token))


__all__: t.MutableSequenceOf[str] = ["FlextAuthProviderService"]

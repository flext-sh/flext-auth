"""FLEXT Auth Provider Service - Flexible flext-core patterns with minimal line count.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthProviderService class with composition.
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Callable,
)
from typing import override

from flext_api import r

from flext_auth import (
    FlextAuthApiKeyProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthJwtProvider,
    FlextAuthLdapProvider,
    FlextAuthOidcProvider,
    FlextAuthRegistry,
    FlextAuthSamlProvider,
    FlextAuthSettings,
    c,
    m,
    p,
    s,
    t,
)
from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider


class FlextAuthProviderService(s):
    """Flexible provider service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

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

    @staticmethod
    def _build_provider_init_config(
        provider_config: t.ConfigurationMapping,
    ) -> t.MappingKV[str, t.Primitives]:
        """Normalize provider settings to base-provider scalar contract."""
        normalized: t.MappingKV[str, t.Primitives] = {
            key: value
            for key, value in provider_config.items()
            if isinstance(value, (bool, int, str))
        }
        return normalized

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
                user.model_dump(),
                token_kind,
                effective_token_type,
                expiry_minutes,
            ),
        )

    def fetch_jwt_provider(self) -> p.Result[FlextAuthJwtProvider]:
        """Fetch registered JWT provider with strict provider type."""
        provider_result = self._providers.get("jwt")
        if provider_result.failure:
            return r[FlextAuthJwtProvider].fail(
                provider_result.error or "JWT provider is not registered",
            )
        provider = provider_result.value
        if not isinstance(provider, FlextAuthJwtProvider):
            return r[FlextAuthJwtProvider].fail("Invalid JWT provider type")
        return r[FlextAuthJwtProvider].ok(provider)

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

    def _register_builtin_providers(self) -> None:
        """Flexible provider registration with conditional loading."""
        if not hasattr(self, "_auth_config"):
            self.logger.error("Configuration is required for provider registration")
            return
        provider_config = self._auth_config.model_dump()
        providers: t.SequenceOf[
            t.Triple[
                t.Auth.ProvidersKey,
                type[p.Auth.FlextAuthBaseProvider],
                Callable[[], bool],
            ]
        ] = [
            ("basic", FlextAuthBasicProvider, lambda: True),
            (
                "jwt",
                FlextAuthJwtProvider,
                lambda: bool(provider_config.get("secret_key")),
            ),
            (
                "ldap",
                FlextAuthLdapProvider,
                lambda: bool(
                    provider_config.get("server") and provider_config.get("base_dn"),
                ),
            ),
            (
                "oauth2",
                FlextAuthOAuth2Provider,
                lambda: bool(
                    provider_config.get("client_id")
                    and provider_config.get("token_endpoint"),
                ),
            ),
            (
                "oidc",
                FlextAuthOidcProvider,
                lambda: bool(provider_config.get("issuer")),
            ),
            (
                "saml",
                FlextAuthSamlProvider,
                lambda: bool(
                    provider_config.get("entity_id") and provider_config.get("sso_url"),
                ),
            ),
            ("certificate", FlextAuthCertificateProvider, lambda: True),
            ("apikey", FlextAuthApiKeyProvider, lambda: True),
        ]
        for name, provider_class, condition in providers:
            if condition():
                try:
                    provider_init_config = self._build_provider_init_config(
                        provider_config,
                    )
                    provider = provider_class(provider_init_config)
                    self._providers.register_provider(
                        name,
                        provider,
                        configuration=provider_init_config,
                    )
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as exc:
                    error_msg: str = str(exc) if exc else "Unknown error"
                    self.logger.warning(
                        "Failed to register %s provider: %s",
                        name,
                        error_msg,
                    )


__all__: t.MutableSequenceOf[str] = ["FlextAuthProviderService"]

"""FLEXT Auth Provider Service - Flexible flext-core patterns with minimal line count.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated patterns
for maximum maintainability. Single FlextAuthProviderService class with composition.
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping

from flext_auth.constants import FlextAuthConstants as c
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols as p

# Import aliases already defined via imports above
# c = FlextAuthConstants
# p = FlextAuthProtocols
# r = FlextResult (via import as r)
# Forward reference to avoid circular import
# Import FlextAuthModels locally in methods where needed
from flext_auth.providers import (
    FlextAuthApiKeyProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthJwtProvider,
    FlextAuthLdapProvider,
    FlextAuthOAuth2Provider,
    FlextAuthOidcProvider,
    FlextAuthSamlProvider,
)
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.registry import FlextAuthRegistry
from flext_auth.settings import FlextAuthSettings
from flext_auth.typings import FlextAuthTypes as t
from flext_core import FlextService as s, r


class FlextAuthProviderService(s[bool]):
    """Flexible provider service using flext-core patterns and railway-oriented programming.

    Python 3.13+ features, minimal line count through consolidated operations.
    Flexible composition with dependency injection and error handling.
    """

    def __init__(self, *, config: FlextAuthSettings | None = None) -> None:
        """Flexible initialization with automatic provider registration."""
        super().__init__()
        if config is not None:
            self._config = config
        self._providers = FlextAuthRegistry()
        self._register_builtin_providers()

    def execute(self) -> r[bool]:
        """Railway-oriented execute with focused service pattern."""
        return r[bool].fail(
            "Use specific provider methods: get_provider, authenticate_user, etc.",
        )

    def _register_builtin_providers(self) -> None:
        """Flexible provider registration with conditional loading."""
        # Fast fail: config is required
        match self._config if hasattr(self, "_config") else None:
            case FlextAuthSettings() as cfg:
                provider_config = cfg.to_provider_config()
            case _:
                self.logger.error("Configuration is required for provider registration")
                return
        # Provider registration mapping with requirements
        providers: list[
            tuple[
                t.Providers.Key,
                type[FlextAuthBaseProvider],
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
                        provider_config
                    )
                    # Instantiate provider with config
                    provider = provider_class(provider_init_config)
                    self._providers.register_provider(
                        name,
                        provider,
                        configuration=provider_config,
                    )
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as e:
                    self.logger.warning(f"Failed to register {name} provider: {e}")

    @staticmethod
    def _build_provider_init_config(
        provider_config: Mapping[str, t.JsonValue],
    ) -> dict[str, str | int | bool]:
        """Normalize provider config to base-provider scalar contract."""
        normalized: dict[str, str | int | bool] = {
            key: value
            for key, value in provider_config.items()
            if isinstance(value, (bool, int, str))
        }
        return normalized

    # =========================================================================
    # CONSOLIDATED PROVIDER MANAGEMENT
    def get_provider(self, name: str) -> r[FlextAuthBaseProvider]:
        """Get registered provider."""
        return self._providers.get(name)

    def get_jwt_provider(self) -> r[FlextAuthJwtProvider]:
        """Get registered JWT provider with strict provider type."""
        provider_result = self._providers.get("jwt")
        if provider_result.is_failure:
            return r[FlextAuthJwtProvider].fail(
                provider_result.error or "JWT provider is not registered",
            )
        provider = provider_result.value
        if not isinstance(provider, FlextAuthJwtProvider):
            return r[FlextAuthJwtProvider].fail("Invalid JWT provider type")
        return r[FlextAuthJwtProvider].ok(provider)

    def register_provider(self, name: str, provider: FlextAuthBaseProvider) -> r[bool]:
        """Register custom provider.

        Returns:
            r[bool]: True if registered successfully, False if failed, error on failure

        """
        return self._providers.register_provider(name, provider).map(lambda _: True)

    def list_providers(self) -> list[str]:
        """List registered provider names."""
        return self._providers.list_providers()

    # Advanced AUTHENTICATION OPERATIONS
    def authenticate_user(
        self,
        username: str,
        password: str,
        provider: str = "basic",
    ) -> r[p.Auth.TokenProtocol]:
        """Railway-oriented user authentication with provider selection."""
        credentials = FlextAuthModels.CredentialValidation(
            username=username,
            password=password,
        )
        return self._providers.get(provider).flat_map(
            lambda auth_provider: auth_provider.authenticate(credentials),
        )

    def generate_token_for_user(
        self,
        user: FlextAuthModels.Auth.AuthIdentity,
        provider: str = "jwt",
        token_type: str = c.Auth.TokenTypes.ACCESS.value,
        expiry_minutes: int | None = None,
    ) -> r[str]:
        """Railway-oriented token generation with direct provider access."""
        return self._providers.get(provider).flat_map(
            lambda p: p.generate_token_for_user(
                user.model_dump(), token_type, expiry_minutes
            ),
        )

    def validate_token(
        self,
        token: str,
        provider: str = "jwt",
    ) -> r[bool]:
        """Railway-oriented token validation with direct provider access."""
        return self._providers.get(provider).flat_map(lambda p: p.validate(token))


__all__ = ["FlextAuthProviderService"]

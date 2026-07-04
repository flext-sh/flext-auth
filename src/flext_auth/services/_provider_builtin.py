"""Built-in auth provider registration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth import (
    FlextAuthApiKeyProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthJwtProvider,
    FlextAuthLdapProvider,
    FlextAuthOidcProvider,
    FlextAuthRfcProvider,
    FlextAuthSamlProvider,
    FlextAuthSettings,
    c,
    p,
    t,
)
from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider

if TYPE_CHECKING:
    from collections.abc import Callable

    from flext_auth.registry import FlextAuthRegistry


class FlextAuthProviderBuiltinRegistration:
    _auth_config: FlextAuthSettings
    _providers: FlextAuthRegistry

    if TYPE_CHECKING:

        @property
        def logger(self) -> p.Logger:
            """Logger supplied by the service facade."""
            raise NotImplementedError

    @staticmethod
    def _build_provider_init_config(
        provider_config: t.ConfigurationMapping,
    ) -> t.MappingKV[str, t.Primitives]:
        """Normalize provider settings to base-provider scalar contract."""
        return FlextAuthRfcProvider.project_to_scalar_config(provider_config) or {}

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
                except c.EXC_BROAD_IO_TYPE as exc:
                    error_msg: str = str(exc) if exc else "Unknown error"
                    self.logger.warning(
                        "Failed to register %s provider: %s",
                        name,
                        error_msg,
                    )


__all__: t.MutableSequenceOf[str] = ["FlextAuthProviderBuiltinRegistration"]

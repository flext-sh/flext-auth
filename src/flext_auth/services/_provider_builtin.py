"""Built-in auth provider registration.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth import FlextAuthSettings, p, t
from flext_auth.providers import (
    FlextAuthApiKeyProvider,
    FlextAuthBasicProvider,
    FlextAuthCertificateProvider,
    FlextAuthJwtProvider,
    FlextAuthLdapProvider,
    FlextAuthOAuth2Provider,
    FlextAuthOidcProvider,
    FlextAuthRfcProvider,
    FlextAuthSamlProvider,
)

if TYPE_CHECKING:
    from collections.abc import Callable


class FlextAuthProviderBuiltinRegistration:
    """Registration mixin provisioning the builtin auth providers."""

    _auth_config: FlextAuthSettings
    _providers: p.Auth.ProviderRegistry

    if TYPE_CHECKING:

        @property
        def logger(self) -> p.Logger:
            """Logger supplied by the service facade."""
            raise NotImplementedError

    @staticmethod
    def _build_provider_init_config(
        provider_config: t.ConfigurationMapping,
    ) -> t.MappingKV[str, t.Primitives]:
        """Normalize provider settings to base-provider scalar contract.

        Returns:
            The resulting ``t.MappingKV[str, t.Primitives]``.

        Raises:
            ValueError: Required provider settings did not produce a configuration.
        """
        projected = FlextAuthRfcProvider.project_to_scalar_config(provider_config)
        if projected is None:
            msg = "Required provider settings did not produce a configuration"
            raise ValueError(msg)
        return projected

    def _register_builtin_providers(self) -> None:
        """Flexible provider registration with conditional loading."""
        provider_config = self._auth_config.Auth.model_dump()
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
                provider_init_config = self._build_provider_init_config(provider_config)
                provider = provider_class(provider_init_config)
                self._providers.register_provider(
                    name,
                    provider,
                    configuration=provider_init_config,
                ).unwrap()


__all__: t.MutableSequenceOf[str] = ["FlextAuthProviderBuiltinRegistration"]

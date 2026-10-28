"""FLEXT Auth API facade.

Public entrypoint kept as a strict facade over service classes.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import MutableSequence, Sequence
from typing import Self

from flext_auth import FlextAuthSettings
from flext_auth.constants import c
from flext_auth.protocols import p
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
from flext_auth.services import (
    FlextAuthApplicationService,
    FlextAuthIdentityService,
    FlextAuthProviderService,
    FlextAuthSessionService,
)
from flext_auth.typings import t
from flext_auth.utilities import u


class FlextAuth(FlextAuthApplicationService):
    """Authentication facade composing identity, token, session and providers."""

    def __init__(
        self,
        *,
        registry: p.Registry | None = None,
        runtime_settings: p.Settings | None = None,
    ) -> None:
        """Compose an isolated graph, or explicitly share injected capabilities."""
        elected_registry = registry if registry is not None else u.build_registry()
        elected_settings = (
            runtime_settings if runtime_settings is not None else FlextAuthSettings()
        )
        identity_manager = u.Auth.FlextAuthUserManager()
        identity_service = FlextAuthIdentityService(
            identity_manager=identity_manager,
            runtime_settings=elected_settings,
        )
        session_service = FlextAuthSessionService(
            provider_service=FlextAuthProviderService(
                registry=elected_registry,
                runtime_settings=elected_settings,
            ),
            user_manager=identity_manager,
            session_manager=u.Auth.FlextAuthSessionManager(),
            runtime_settings=elected_settings,
        )
        super().__init__(
            registry=elected_registry,
            identity_service=identity_service,
            session_service=session_service,
            runtime_settings=elected_settings,
        )
        if registry is not None:
            return
        provider_config = {
            key: value
            for key, value in self.settings.Auth.model_dump().items()
            if isinstance(value, (str, int, bool))
        }
        providers: Sequence[
            tuple[t.Auth.ProvidersKey, type[p.Auth.FlextAuthBaseProvider], bool]
        ] = (
            (c.Auth.ProviderTypes.BASIC.value, FlextAuthBasicProvider, True),
            (
                c.Auth.ProviderTypes.JWT.value,
                FlextAuthJwtProvider,
                bool(provider_config.get("secret_key")),
            ),
            (
                c.Auth.ProviderTypes.LDAP.value,
                FlextAuthLdapProvider,
                bool(provider_config.get("server") and provider_config.get("base_dn")),
            ),
            (
                c.Auth.ProviderTypes.OAUTH2.value,
                FlextAuthOAuth2Provider,
                bool(
                    provider_config.get("client_id")
                    and provider_config.get("token_endpoint")
                ),
            ),
            (
                c.Auth.ProviderTypes.OIDC.value,
                FlextAuthOidcProvider,
                bool(provider_config.get("issuer")),
            ),
            (
                c.Auth.ProviderTypes.SAML.value,
                FlextAuthSamlProvider,
                bool(
                    provider_config.get("entity_id") and provider_config.get("sso_url")
                ),
            ),
            (
                c.Auth.ProviderTypes.CERTIFICATE.value,
                FlextAuthCertificateProvider,
                True,
            ),
            (c.Auth.ProviderTypes.APIKEY.value, FlextAuthApiKeyProvider, True),
        )
        for name, provider_type, enabled in providers:
            if self.has_provider(name):
                self.fetch_provider(name).unwrap()
            elif enabled:
                self.register_provider(
                    name,
                    provider_type(provider_config),
                    configuration=provider_config,
                ).unwrap()

    @classmethod
    def quick_start(cls, *, create_admin_user: bool = True) -> Self:
        """Compose the API and require requested admin provisioning to succeed.

        Returns:
            The composed authentication API.

        """
        auth = cls()
        if create_admin_user:
            auth.register_user(
                c.Auth.DEFAULT_ADMIN_USERNAME,
                c.Auth.DEFAULT_ADMIN_EMAIL,
                c.Auth.DEFAULT_ADMIN_CREDENTIAL,
                roles=c.Auth.DEFAULT_ADMIN_ROLES,
            ).unwrap()
        return auth


auth: p.Auth.Service = FlextAuth()
"""Public application instance, explicitly composed at the API boundary."""


__all__: MutableSequence[str] = ["FlextAuth", "auth"]

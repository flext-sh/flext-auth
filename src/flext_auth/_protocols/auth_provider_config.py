# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_auth/_protocols/auth_provider_config
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import FlextApiProtocols

if TYPE_CHECKING:
    from flext_api import p

    from flext_auth import t
    from flext_auth._protocols import (
        FlextAuthProtocolsAuthIdentity,
        FlextAuthProtocolsAuthService,
        FlextAuthProtocolsAuthSession,
    )


class FlextAuthProtocolsAuthProviderConfig:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class RegistryPortOptions(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def registry(self) -> p.Registry:
            """Instance-scoped registry supplied by the API composition."""
            ...

    @runtime_checkable
    class ApplicationPortOptions(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def identity_service(self) -> FlextAuthProtocolsAuthService.IdentityService:
            """Identity operations using the composed user manager."""
            ...

        @property
        def session_service(self) -> FlextAuthProtocolsAuthService.SessionService:
            """Token and session operations using the same identity store."""
            ...

    @runtime_checkable
    class IdentityPortOptions(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def identity_manager(self) -> FlextAuthProtocolsAuthIdentity.IdentityManager:
            """Identity manager explicitly supplied by the API."""
            ...

    @runtime_checkable
    class SessionPortOptions(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def provider_service(self) -> FlextAuthProtocolsAuthService.ProviderService:
            """Provider resolver bound to the composed registry."""
            ...

        @property
        def user_manager(self) -> FlextAuthProtocolsAuthIdentity.IdentityManager:
            """The same identity manager used by identity operations."""
            ...

        @property
        def session_manager(self) -> FlextAuthProtocolsAuthSession.SessionManager:
            """Session manager supplied by the API composition."""
            ...

    @runtime_checkable
    class ProviderIdentityConfig(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        name: str
        type: str
        enabled: bool
        provider_type: str | None

        def __contains__(self, key: str) -> bool:
            """Report whether a configuration field is declared."""
            ...

        @property
        def configured(self) -> bool:
            """Whether the provider declares its required name and type."""
            ...

    @runtime_checkable
    class ProviderTokenConfig(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        secret_key: str | None
        algorithm: str | None
        token_expiry_minutes: t.PositiveInt | None
        refresh_expiry_days: int | None
        audience: str | None
        issuer: str | None

    @runtime_checkable
    class ProviderOAuthConfig(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        client_id: str | None
        client_secret: str | None
        authorization_endpoint: str | None
        token_endpoint: str | None
        redirect_uri: str | None
        scope: str | None
        flow: str | None
        use_pkce: bool | None
        token_endpoint_auth_method: str | None

    @runtime_checkable
    class ProviderKerberosConfig(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        realm: str | None
        kdc_host: str | None
        kdc_port: t.PortNumber | None
        service_principal: str | None
        keytab_path: str | None

    @runtime_checkable
    class ProviderSamlConfig(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        entity_id: str | None
        sso_url: str | None
        slo_url: str | None
        x509_cert: str | None

    @runtime_checkable
    class ProviderLdapConfig(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        ldap_url: str | None
        bind_dn: str | None
        base_dn: str | None
        search_filter: str | None

    @runtime_checkable
    class ProviderConfig(
        ProviderLdapConfig,
        ProviderSamlConfig,
        ProviderKerberosConfig,
        ProviderOAuthConfig,
        ProviderTokenConfig,
        ProviderIdentityConfig,
        Protocol,
    ):
        """Structural data contract projected from the owning model."""


__all__: list[str] = [
    "FlextAuthProtocolsAuthProviderConfig",
]

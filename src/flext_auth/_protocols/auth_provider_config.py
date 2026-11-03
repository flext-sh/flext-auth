# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_auth/_protocols/auth_provider_config
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import FlextApiProtocols

from flext_auth import t

if TYPE_CHECKING:
    from flext_api import p

    from flext_auth._protocols import (
        FlextAuthProtocolsAuthIdentity,
        FlextAuthProtocolsAuthService,
        FlextAuthProtocolsAuthSession,
    )


class FlextAuthProtocolsAuthProviderConfig:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class RegistryPortOptions(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def registry(self) -> p.Registry:
            """Instance-scoped registry supplied by the API composition."""
            ...

    @runtime_checkable
    class ApplicationPortOptions(FlextApiProtocols.Model, Protocol):
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
    class IdentityPortOptions(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def identity_manager(self) -> FlextAuthProtocolsAuthIdentity.IdentityManager:
            """Identity manager explicitly supplied by the API."""
            ...

    @runtime_checkable
    class SessionPortOptions(FlextApiProtocols.Model, Protocol):
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
    class ProviderConfig(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """Provider name."""
            ...

        @property
        def type(self) -> str:
            """Provider type."""
            ...

        @property
        def enabled(self) -> bool:
            """Enabled status."""
            ...

        @property
        def provider_type(self) -> str | None:
            """Authentication provider type."""
            ...

        @property
        def secret_key(self) -> str | None:
            """Provider secret key."""
            ...

        @property
        def algorithm(self) -> str | None:
            """Token signing algorithm."""
            ...

        @property
        def token_expiry_minutes(self) -> t.PositiveInt | None:
            """Token expiry in minutes."""
            ...

        @property
        def refresh_expiry_days(self) -> int | None:
            """Refresh token expiry in days."""
            ...

        @property
        def client_id(self) -> str | None:
            """OAuth client identifier."""
            ...

        @property
        def client_secret(self) -> str | None:
            """OAuth client secret."""
            ...

        @property
        def authorization_endpoint(self) -> str | None:
            """OAuth authorization endpoint URL."""
            ...

        @property
        def token_endpoint(self) -> str | None:
            """OAuth token endpoint URL."""
            ...

        @property
        def redirect_uri(self) -> str | None:
            """OAuth redirect URI."""
            ...

        @property
        def scope(self) -> str | None:
            """OAuth scope."""
            ...

        @property
        def audience(self) -> str | None:
            """Token audience claim."""
            ...

        @property
        def issuer(self) -> str | None:
            """Token issuer claim."""
            ...

        @property
        def realm(self) -> str | None:
            """Kerberos realm."""
            ...

        @property
        def kdc_host(self) -> str | None:
            """Kerberos KDC hostname."""
            ...

        @property
        def kdc_port(self) -> t.PortNumber | None:
            """Kerberos KDC port."""
            ...

        @property
        def service_principal(self) -> str | None:
            """Kerberos service principal."""
            ...

        @property
        def keytab_path(self) -> str | None:
            """Kerberos keytab file path."""
            ...

        @property
        def entity_id(self) -> str | None:
            """SAML entity identifier."""
            ...

        @property
        def sso_url(self) -> str | None:
            """SAML SSO endpoint URL."""
            ...

        @property
        def slo_url(self) -> str | None:
            """SAML SLO endpoint URL."""
            ...

        @property
        def x509_cert(self) -> str | None:
            """SAML X.509 certificate."""
            ...

        @property
        def ldap_url(self) -> str | None:
            """LDAP server URL."""
            ...

        @property
        def bind_dn(self) -> str | None:
            """LDAP bind distinguished name."""
            ...

        @property
        def base_dn(self) -> str | None:
            """LDAP base distinguished name."""
            ...

        @property
        def search_filter(self) -> str | None:
            """LDAP search filter."""
            ...

        @property
        def flow(self) -> str | None:
            """OAuth flow type."""
            ...

        @property
        def use_pkce(self) -> bool | None:
            """Enable PKCE for OAuth."""
            ...

        @property
        def token_endpoint_auth_method(self) -> str | None:
            """Token endpoint authentication method."""
            ...

        def __contains__(self, key: str) -> bool:
            """Report whether a configuration field is declared."""
            ...

        @property
        def configured(self) -> bool:
            """Whether the provider declares its required name and type."""
            ...


__all__: list[str] = [
    "FlextAuthProtocolsAuthProviderConfig",
]

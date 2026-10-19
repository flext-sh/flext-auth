"""Authentication provider configuration models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated

from flext_api import m

from flext_auth import p, t


class FlextAuthModelsAuthProviderConfig:
    """Provider configuration model namespace."""

    class RegistryPortOptions(m.ArbitraryTypesModel):
        """Required registry supplied by the API composition root."""

        registry: t.Port[p.Registry] = m.Field(
            exclude=True,
            description="Instance-scoped registry supplied by the API composition.",
        )

    class ApplicationPortOptions(m.ArbitraryTypesModel):
        """Required identity and session domain capabilities."""

        identity_service: t.Port[p.Auth.IdentityService] = m.Field(
            exclude=True,
            description="Identity operations using the composed user manager.",
        )
        session_service: t.Port[p.Auth.SessionService] = m.Field(
            exclude=True,
            description="Token and session operations using the same identity store.",
        )

    class IdentityPortOptions(m.ArbitraryTypesModel):
        """Identity persistence required by identity operations."""

        identity_manager: t.Port[p.Auth.IdentityManager] = m.Field(
            exclude=True,
            description="Identity manager explicitly supplied by the API.",
        )

    class SessionPortOptions(m.ArbitraryTypesModel):
        """Required provider and session persistence capabilities."""

        provider_service: t.Port[p.Auth.ProviderService] = m.Field(
            exclude=True,
            description="Provider resolver bound to the composed registry.",
        )
        user_manager: t.Port[p.Auth.IdentityManager] = m.Field(
            exclude=True,
            description="The same identity manager used by identity operations.",
        )
        session_manager: t.Port[p.Auth.SessionManager] = m.Field(
            exclude=True,
            description="Session manager supplied by the API composition.",
        )

    class ProviderConfig(m.FlexibleModel):
        """Generic provider configuration (immutable value object)."""

        name: Annotated[str, m.Field(..., description="Provider name")]
        type: Annotated[str, m.Field(..., description="Provider type")]
        enabled: Annotated[bool, m.Field(description="Enabled status")] = True

        # Extended configuration fields (migrated from TypedDict)
        # All optional to support various provider types
        provider_type: Annotated[
            str | None,
            m.Field(description="Authentication provider type"),
        ] = None
        secret_key: Annotated[
            str | None,
            m.Field(description="Provider secret key"),
        ] = None
        algorithm: Annotated[
            str | None,
            m.Field(description="Token signing algorithm"),
        ] = None
        token_expiry_minutes: Annotated[
            t.PositiveInt | None,
            m.Field(description="Token expiry in minutes"),
        ] = None
        refresh_expiry_days: Annotated[
            int | None,
            m.Field(description="Refresh token expiry in days"),
        ] = None
        client_id: Annotated[
            str | None,
            m.Field(description="OAuth client identifier"),
        ] = None
        client_secret: Annotated[
            str | None,
            m.Field(description="OAuth client secret"),
        ] = None
        authorization_endpoint: Annotated[
            str | None,
            m.Field(description="OAuth authorization endpoint URL"),
        ] = None
        token_endpoint: Annotated[
            str | None,
            m.Field(description="OAuth token endpoint URL"),
        ] = None
        redirect_uri: Annotated[
            str | None,
            m.Field(description="OAuth redirect URI"),
        ] = None
        scope: Annotated[str | None, m.Field(description="OAuth scope")] = None
        audience: Annotated[str | None, m.Field(description="Token audience claim")] = (
            None
        )
        issuer: Annotated[str | None, m.Field(description="Token issuer claim")] = None
        realm: Annotated[str | None, m.Field(description="Kerberos realm")] = None
        kdc_host: Annotated[
            str | None,
            m.Field(description="Kerberos KDC hostname"),
        ] = None
        kdc_port: Annotated[
            t.PortNumber | None,
            m.Field(description="Kerberos KDC port"),
        ] = None
        service_principal: Annotated[
            str | None,
            m.Field(description="Kerberos service principal"),
        ] = None
        keytab_path: Annotated[
            str | None,
            m.Field(description="Kerberos keytab file path"),
        ] = None
        entity_id: Annotated[
            str | None,
            m.Field(description="SAML entity identifier"),
        ] = None
        sso_url: Annotated[str | None, m.Field(description="SAML SSO endpoint URL")] = (
            None
        )
        slo_url: Annotated[str | None, m.Field(description="SAML SLO endpoint URL")] = (
            None
        )
        x509_cert: Annotated[
            str | None,
            m.Field(description="SAML X.509 certificate"),
        ] = None
        ldap_url: Annotated[str | None, m.Field(description="LDAP server URL")] = None
        bind_dn: Annotated[
            str | None,
            m.Field(description="LDAP bind distinguished name"),
        ] = None
        base_dn: Annotated[
            str | None,
            m.Field(description="LDAP base distinguished name"),
        ] = None
        search_filter: Annotated[
            str | None,
            m.Field(description="LDAP search filter"),
        ] = None
        flow: Annotated[str | None, m.Field(description="OAuth flow type")] = None
        use_pkce: Annotated[
            bool | None,
            m.Field(description="Enable PKCE for OAuth"),
        ] = None
        token_endpoint_auth_method: Annotated[
            str | None,
            m.Field(description="Token endpoint authentication method"),
        ] = None

        def __contains__(self, key: str) -> bool:
            """Report whether a configuration field is declared.

            Args:
                key: Field name to look up.

            Returns:
                Whether the field exists on this model.

            """
            return key in self.__class__.model_fields

        @property
        def configured(self) -> bool:
            """Whether the provider declares its required name and type."""
            return bool(self.name and self.type)


__all__: list[str] = ["FlextAuthModelsAuthProviderConfig"]

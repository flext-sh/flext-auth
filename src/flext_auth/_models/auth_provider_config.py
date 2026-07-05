"""Authentication provider configuration models."""

from __future__ import annotations

from typing import Annotated

from flext_api import m, u

from flext_auth.typings import t


class FlextAuthModelsAuthProviderConfig:
    class ProviderConfig(m.FlexibleModel):
        """Generic provider configuration (immutable value object)."""

        name: Annotated[str, u.Field(..., description="Provider name")]
        type: Annotated[str, u.Field(..., description="Provider type")]
        enabled: Annotated[bool, u.Field(description="Enabled status")] = True

        # Extended configuration fields (migrated from TypedDict)
        # All optional to support various provider types
        provider_type: Annotated[
            str | None,
            u.Field(description="Authentication provider type"),
        ] = None
        secret_key: Annotated[
            str | None,
            u.Field(description="Provider secret key"),
        ] = None
        algorithm: Annotated[
            str | None,
            u.Field(description="Token signing algorithm"),
        ] = None
        token_expiry_minutes: Annotated[
            t.PositiveInt | None,
            u.Field(description="Token expiry in minutes"),
        ] = None
        refresh_expiry_days: Annotated[
            int | None,
            u.Field(description="Refresh token expiry in days"),
        ] = None
        client_id: Annotated[
            str | None,
            u.Field(description="OAuth client identifier"),
        ] = None
        client_secret: Annotated[
            str | None,
            u.Field(description="OAuth client secret"),
        ] = None
        authorization_endpoint: Annotated[
            str | None,
            u.Field(description="OAuth authorization endpoint URL"),
        ] = None
        token_endpoint: Annotated[
            str | None,
            u.Field(description="OAuth token endpoint URL"),
        ] = None
        redirect_uri: Annotated[
            str | None,
            u.Field(description="OAuth redirect URI"),
        ] = None
        scope: Annotated[str | None, u.Field(description="OAuth scope")] = None
        audience: Annotated[str | None, u.Field(description="Token audience claim")] = (
            None
        )
        issuer: Annotated[str | None, u.Field(description="Token issuer claim")] = None
        realm: Annotated[str | None, u.Field(description="Kerberos realm")] = None
        kdc_host: Annotated[
            str | None,
            u.Field(description="Kerberos KDC hostname"),
        ] = None
        kdc_port: Annotated[
            t.PortNumber | None,
            u.Field(description="Kerberos KDC port"),
        ] = None
        service_principal: Annotated[
            str | None,
            u.Field(description="Kerberos service principal"),
        ] = None
        keytab_path: Annotated[
            str | None,
            u.Field(description="Kerberos keytab file path"),
        ] = None
        entity_id: Annotated[
            str | None,
            u.Field(description="SAML entity identifier"),
        ] = None
        sso_url: Annotated[str | None, u.Field(description="SAML SSO endpoint URL")] = (
            None
        )
        slo_url: Annotated[str | None, u.Field(description="SAML SLO endpoint URL")] = (
            None
        )
        x509_cert: Annotated[
            str | None,
            u.Field(description="SAML X.509 certificate"),
        ] = None
        ldap_url: Annotated[str | None, u.Field(description="LDAP server URL")] = None
        bind_dn: Annotated[
            str | None,
            u.Field(description="LDAP bind distinguished name"),
        ] = None
        base_dn: Annotated[
            str | None,
            u.Field(description="LDAP base distinguished name"),
        ] = None
        search_filter: Annotated[
            str | None,
            u.Field(description="LDAP search filter"),
        ] = None
        flow: Annotated[str | None, u.Field(description="OAuth flow type")] = None
        use_pkce: Annotated[
            bool | None,
            u.Field(description="Enable PKCE for OAuth"),
        ] = None
        token_endpoint_auth_method: Annotated[
            str | None,
            u.Field(description="Token endpoint authentication method"),
        ] = None

        def __contains__(self, key: str) -> bool:
            """Dict-like containment check."""
            return key in self.__class__.model_fields

        @property
        def configured(self) -> bool:
            """Check if configured."""
            return bool(self.name and self.type)


__all__: list[str] = ["FlextAuthModelsAuthProviderConfig"]

"""Authentication response and wrapper models."""

from __future__ import annotations

from types import MappingProxyType
from typing import Annotated, ClassVar

from flext_api import m, p, u

from flext_auth import c, p, t


class FlextAuthModelsAuthResponse:
    class CredentialValidation(m.Value):
        """Credential validation request (immutable value object)."""

        username: Annotated[str, u.Field(..., description="Username")]
        password: Annotated[str, u.Field(..., description="Password", exclude=True)]
        metadata: t.JsonMapping = u.Field(
            default_factory=MappingProxyType,
            description="Metadata for the credential validation",
        )

    # =========================================================================
    # AUTHENTICATION RESPONSE - Generic response
    # =========================================================================

    class AuthResponse(m.Value):
        """Generic authentication response (immutable value object)."""

        success: Annotated[bool, u.Field(..., description="Authentication success")]
        identity: t.JsonMapping = u.Field(
            default_factory=MappingProxyType,
            description="Identity information for the API key",
        )
        token: Annotated[str, u.Field(description="Token", exclude=True)] = ""
        message: Annotated[str, u.Field(description="Response message")] = ""
        metadata: t.JsonMapping = u.Field(
            default_factory=MappingProxyType,
            description="Metadata for the authentication response",
        )

    # =========================================================================
    # OAUTH2 TOKEN RESPONSE - OAuth2 token exchange result
    # =========================================================================

    class OAuth2TokenResponse(m.Value):
        """OAuth2 token response from token endpoint."""

        access_token: Annotated[str, u.Field(..., description="Access token")]
        token_type: Annotated[
            str,
            u.Field(description="Token type"),
        ] = c.Auth.JWT_DEFAULT_TOKEN_TYPE
        expires_in: Annotated[
            t.NonNegativeInt,
            u.Field(description="Expiry seconds"),
        ] = 3600
        scope: Annotated[str, u.Field(description="Granted scope")] = ""
        refresh_token: Annotated[
            str,
            u.Field(
                description="Refresh token",
                exclude=True,
            ),
        ] = ""

    # =========================================================================
    # KERBEROS TICKET DATA - Kerberos ticket information
    # =========================================================================

    class KerberosTicketData(m.Value):
        """Kerberos ticket information."""

        ticket: Annotated[str, u.Field(..., description="Kerberos ticket")]
        principal: Annotated[
            str,
            u.Field(description="Kerberos principal"),
        ] = ""
        realm: Annotated[str, u.Field(description="Kerberos realm")] = ""

    # =========================================================================
    # PROVIDERS NAMESPACE - Provider metadata and related models
    # =========================================================================

    # =========================================================================
    # REGISTRY WRAPPER MODELS - Internal registry wrappers
    # =========================================================================

    class ProviderWrapper(m.Value):
        """Wrapper for auth provider instances."""

        model_config: ClassVar[t.ConfigDict] = m.ConfigDict(
            arbitrary_types_allowed=True,
        )

        category: Annotated[str, u.Field(description="Provider category")]
        provider: Annotated[
            p.Auth.FlextAuthBaseProvider,
            u.Field(description="Provider instance"),
        ]

    class ConfigWrapper(m.Value):
        """Protocol-conformant wrapper for settings data."""

        category: Annotated[str, u.Field(description="Config category")]
        data: Annotated[t.ConfigurationMapping, u.Field(description="Config data")]

    class MetadataWrapper(m.Value):
        """Protocol-conformant wrapper for metadata."""

        category: Annotated[str, u.Field(description="Metadata category")]
        data: Annotated[p.Value, u.Field(description="Metadata")]

    class Providers:
        """Provider-related models namespace."""

        class Metadata(m.Value):
            """Provider metadata for registry."""

            name: Annotated[str, u.Field(..., description="Provider name")]
            version: Annotated[
                str,
                u.Field(description="Provider version"),
            ] = "1.0.0"
            capabilities: t.VariadicTuple[str] = u.Field(
                default_factory=tuple,
                description="Provider capabilities",
            )
            extras: t.JsonMapping = u.Field(
                default_factory=MappingProxyType,
                description="Extra attributes for the identity",
            )


__all__: list[str] = ["FlextAuthModelsAuthResponse"]

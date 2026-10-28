"""Authentication response and wrapper models.

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

from types import MappingProxyType
from typing import Annotated

from flext_api import m

from flext_auth import c, p, t


class FlextAuthModelsAuthResponse:
    """Authentication response and wrapper model namespace."""

    class CredentialValidation(m.Value):
        """Credential validation request (immutable value object)."""

        username: Annotated[str, m.Field(..., description="Username")]
        password: Annotated[str, m.Field(..., description="Password", exclude=True)]
        metadata: t.JsonMapping = m.Field(
            default_factory=lambda: MappingProxyType[str, t.JsonValue]({}),
            description="Metadata for the credential validation",
        )

    # =========================================================================
    # AUTHENTICATION RESPONSE - Generic response
    # =========================================================================

    class AuthResponse(m.Value):
        """Generic authentication response (immutable value object)."""

        success: Annotated[bool, m.Field(..., description="Authentication success")]
        identity: t.JsonMapping = m.Field(
            default_factory=lambda: MappingProxyType[str, t.JsonValue]({}),
            description="Identity information for the API key",
        )
        token: Annotated[str, m.Field(description="Token", exclude=True)] = ""
        message: Annotated[str, m.Field(description="Response message")] = ""
        metadata: t.JsonMapping = m.Field(
            default_factory=lambda: MappingProxyType[str, t.JsonValue]({}),
            description="Metadata for the authentication response",
        )

    # =========================================================================
    # OAUTH2 TOKEN RESPONSE - OAuth2 token exchange result
    # =========================================================================

    class OAuth2TokenResponse(m.Value):
        """OAuth2 token response from token endpoint."""

        access_token: Annotated[str, m.Field(..., description="Access token")]
        token_type: Annotated[str, m.Field(description="Token type")] = (
            c.Auth.JWT_DEFAULT_TOKEN_TYPE
        )
        expires_in: Annotated[
            t.NonNegativeInt,
            m.Field(description="Expiry seconds"),
        ] = 3600
        scope: Annotated[str, m.Field(description="Granted scope")] = ""
        refresh_token: Annotated[
            str,
            m.Field(description="Refresh token", exclude=True),
        ] = ""

    # =========================================================================
    # KERBEROS TICKET DATA - Kerberos ticket information
    # =========================================================================

    class KerberosTicketData(m.Value):
        """Kerberos ticket information."""

        ticket: Annotated[str, m.Field(..., description="Kerberos ticket")]
        principal: Annotated[str, m.Field(description="Kerberos principal")] = ""
        realm: Annotated[str, m.Field(description="Kerberos realm")] = ""

    # =========================================================================
    # PROVIDERS NAMESPACE - Provider metadata and related models
    # =========================================================================

    # =========================================================================
    # REGISTRY WRAPPER MODELS - Internal registry wrappers
    # =========================================================================

    class ProviderWrapper(m.ContractModel):
        """One registration preserving provider identity, config and metadata."""

        category: Annotated[str, m.Field(description="Provider category")]
        provider: t.Port[p.Auth.FlextAuthBaseProvider] = m.Field(
            exclude=True,
            description="Provider instance, retained by identity.",
        )
        configuration: t.ConfigurationMapping | None = m.Field(
            default=None,
            description="Validated provider configuration.",
        )
        metadata: t.Port[p.Auth.ProviderMetadata] | None = m.Field(
            default=None,
            exclude=True,
            description="Original domain metadata of this provider registration.",
        )

    class Providers:
        """Provider-related models namespace."""

        class Metadata(m.Value):
            """Provider metadata for registry."""

            name: Annotated[str, m.Field(..., description="Provider name")]
            version: Annotated[str, m.Field(description="Provider version")] = (
                c.Auth.PROVIDER_VERSION
            )
            capabilities: tuple[str, ...] = m.Field(
                default_factory=tuple,
                description="Provider capabilities",
            )
            extras: t.JsonMapping = m.Field(
                default_factory=lambda: MappingProxyType[str, t.JsonValue]({}),
                description="Extra attributes for the identity",
            )


__all__: list[str] = ["FlextAuthModelsAuthResponse"]

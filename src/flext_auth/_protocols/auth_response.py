# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_auth/_protocols/auth_response
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import FlextApiProtocols

from flext_auth import t

if TYPE_CHECKING:
    from flext_auth._protocols import FlextAuthProtocolsAuthProvider


class FlextAuthProtocolsAuthResponse:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class CredentialValidation(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def username(self) -> str:
            """Username."""
            ...

        @property
        def password(self) -> str:
            """Password."""
            ...

        @property
        def metadata(self) -> t.JsonMapping:
            """Metadata for the credential validation."""
            ...

    @runtime_checkable
    class AuthResponse(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def success(self) -> bool:
            """Authentication success."""
            ...

        @property
        def identity(self) -> t.JsonMapping:
            """Identity information for the API key."""
            ...

        @property
        def token(self) -> str:
            """Token."""
            ...

        @property
        def message(self) -> str:
            """Response message."""
            ...

        @property
        def metadata(self) -> t.JsonMapping:
            """Metadata for the authentication response."""
            ...

    @runtime_checkable
    class OAuth2TokenResponse(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def access_token(self) -> str:
            """Access token."""
            ...

        @property
        def token_type(self) -> str:
            """Token type."""
            ...

        @property
        def expires_in(self) -> t.NonNegativeInt:
            """Expiry seconds."""
            ...

        @property
        def scope(self) -> str:
            """Granted scope."""
            ...

        @property
        def refresh_token(self) -> str:
            """Refresh token."""
            ...

    @runtime_checkable
    class KerberosTicketData(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def ticket(self) -> str:
            """Kerberos ticket."""
            ...

        @property
        def principal(self) -> str:
            """Kerberos principal."""
            ...

        @property
        def realm(self) -> str:
            """Kerberos realm."""
            ...

    @runtime_checkable
    class ProviderWrapper(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def category(self) -> str:
            """Provider category."""
            ...

        @property
        def provider(self) -> FlextAuthProtocolsAuthProvider.FlextAuthBaseProvider:
            """Provider instance, retained by identity."""
            ...

        @property
        def configuration(self) -> t.ConfigurationMapping | None:
            """Validated provider configuration."""
            ...

        @property
        def metadata(self) -> FlextAuthProtocolsAuthProvider.ProviderMetadata | None:
            """Original domain metadata of this provider registration."""
            ...

    @runtime_checkable
    class Metadata(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def name(self) -> str:
            """Provider name."""
            ...

        @property
        def version(self) -> str:
            """Provider version."""
            ...

        @property
        def capabilities(self) -> tuple[str, ...]:
            """Provider capabilities."""
            ...

        @property
        def extras(self) -> t.JsonMapping:
            """Extra attributes for the identity."""
            ...


__all__: list[str] = [
    "FlextAuthProtocolsAuthResponse",
]

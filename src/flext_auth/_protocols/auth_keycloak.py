# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_auth/_protocols/auth_keycloak
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_api import FlextApiProtocols


class FlextAuthProtocolsAuthKeycloak:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class KeycloakClaims(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        groups: tuple[str, ...]

        @property
        def realm_access(
            self,
        ) -> FlextAuthProtocolsAuthKeycloak.KeycloakClaimsRealmAccess:
            """Realm-level role grants."""
            ...

    @runtime_checkable
    class KeycloakClaimsRealmAccess(FlextApiProtocols.BaseModel, Protocol):
        """Structural data contract projected from the owning model."""

        roles: tuple[str, ...]


__all__: list[str] = [
    "FlextAuthProtocolsAuthKeycloak",
]

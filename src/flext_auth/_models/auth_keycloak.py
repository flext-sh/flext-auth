"""Keycloak access-token claim models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import m


class FlextAuthModelsAuthKeycloak:
    """Keycloak access-token claim model namespace."""

    class KeycloakClaims(m.FlexibleInternalModel):
        """The authorization claims of a Keycloak access token."""

        class RealmAccess(m.FlexibleInternalModel):
            """The ``realm_access`` claim of a Keycloak access token."""

            roles: tuple[str, ...] = m.Field(
                default=(),
                description="Realm roles granted to the token subject.",
            )

        groups: tuple[str, ...] = m.Field(
            default=(),
            description="Group names or paths of the token subject.",
        )
        realm_access: RealmAccess = m.Field(
            default_factory=RealmAccess,
            description="Realm-level role grants.",
        )


__all__: list[str] = ["FlextAuthModelsAuthKeycloak"]

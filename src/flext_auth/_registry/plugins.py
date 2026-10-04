"""Auth registry plugin delegation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import c, p, r, t


class FlextAuthRegistryPlugins:
    _registry: p.Registry

    def fetch_plugin(
        self,
        category: str,
        name: str,
        *,
        scope: c.RegistrationScope = c.RegistrationScope.INSTANCE,
    ) -> p.Result[t.JsonPayload | None]:
        """Delegate plugin lookup to the canonical registry.

        Returns:
            The resulting ``p.Result[t.JsonPayload | None]``.
        """
        return r[t.JsonPayload | None].from_result(
            self._registry.fetch_plugin(category, name, scope=scope),
        )

    def list_plugins(
        self,
        category: str,
        *,
        scope: c.RegistrationScope = c.RegistrationScope.INSTANCE,
    ) -> p.Result[t.StrSequence]:
        """Delegate plugin listing to the canonical registry.

        Returns:
            The resulting ``p.Result[t.StrSequence]``.
        """
        return r[t.StrSequence].from_result(
            self._registry.list_plugins(category, scope=scope),
        )

    def unregister_plugin(
        self,
        category: str,
        name: str,
        *,
        scope: c.RegistrationScope = c.RegistrationScope.INSTANCE,
    ) -> p.Result[bool]:
        """Delegate plugin removal to the canonical registry.

        Returns:
            The resulting ``p.Result[bool]``.
        """
        return r[bool].from_result(
            self._registry.unregister_plugin(category, name, scope=scope),
        )


__all__: list[str] = ["FlextAuthRegistryPlugins"]

"""Auth registry plugin delegation.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import c, p, r, t


class FlextAuthRegistryPlugins:
    """Delegation layer over the canonical plugin registry."""

    _registry: p.Registry

    def fetch_plugin(
        self,
        category: str,
        name: str,
        *,
        scope: c.RegistrationScope = c.RegistrationScope.INSTANCE,
    ) -> p.Result[t.JsonPayload | None]:
        """Delegate plugin lookup to the canonical registry.

        Args:
            category: Registry category to search.
            name: Registered plugin name.
            scope: Registration scope to resolve.

        Returns:
            The stored plugin payload, or ``None`` when absent.

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

        Args:
            category: Registry category to list.
            scope: Registration scope to resolve.

        Returns:
            Names of the plugins registered in the category.

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

        Args:
            category: Registry category to remove from.
            name: Registered plugin name.
            scope: Registration scope to remove.

        Returns:
            Success when the plugin entry was removed.

        """
        return r[bool].from_result(
            self._registry.unregister_plugin(category, name, scope=scope),
        )


__all__: list[str] = ["FlextAuthRegistryPlugins"]

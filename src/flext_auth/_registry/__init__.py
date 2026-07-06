# AUTO-GENERATED FILE — Regenerate with: make gen
"""Registry package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._registry.base import FlextAuthRegistryBase
    from flext_auth._registry.lookup import FlextAuthRegistryLookup
    from flext_auth._registry.metadata import FlextAuthRegistryMetadata
    from flext_auth._registry.mutation import FlextAuthRegistryMutation
    from flext_auth._registry.plugins import FlextAuthRegistryPlugins
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".base": ("FlextAuthRegistryBase",),
        ".lookup": ("FlextAuthRegistryLookup",),
        ".metadata": ("FlextAuthRegistryMetadata",),
        ".mutation": ("FlextAuthRegistryMutation",),
        ".plugins": ("FlextAuthRegistryPlugins",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

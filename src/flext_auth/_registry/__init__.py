# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Registry package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .base import FlextAuthRegistryBase as FlextAuthRegistryBase
    from .lookup import FlextAuthRegistryLookup as FlextAuthRegistryLookup
    from .metadata import FlextAuthRegistryMetadata as FlextAuthRegistryMetadata
    from .mutation import FlextAuthRegistryMutation as FlextAuthRegistryMutation
    from .plugins import FlextAuthRegistryPlugins as FlextAuthRegistryPlugins

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".base": ("FlextAuthRegistryBase",),
    ".lookup": ("FlextAuthRegistryLookup",),
    ".metadata": ("FlextAuthRegistryMetadata",),
    ".mutation": ("FlextAuthRegistryMutation",),
    ".plugins": ("FlextAuthRegistryPlugins",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextAuthRegistryBase",
    "FlextAuthRegistryLookup",
    "FlextAuthRegistryMetadata",
    "FlextAuthRegistryMutation",
    "FlextAuthRegistryPlugins",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Typings package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth import FlextAuthTypesAuth
    from .base import FlextAuthTypesBase


__all__: tuple[str, ...] = ("FlextAuthTypesAuth", "FlextAuthTypesBase")

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth": ("FlextAuthTypesAuth",),
            ".base": ("FlextAuthTypesBase",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

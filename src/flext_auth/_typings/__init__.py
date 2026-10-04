# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Typings package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._typings.auth import FlextAuthTypesAuth
    from flext_auth._typings.base import FlextAuthTypesBase


__all__: tuple[str, ...] = ("FlextAuthTypesAuth", "FlextAuthTypesBase")

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth": ("FlextAuthTypesAuth",),
            ".base": ("FlextAuthTypesBase",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

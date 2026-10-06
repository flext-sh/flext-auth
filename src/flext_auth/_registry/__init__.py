# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Registry package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._registry.base import FlextAuthRegistryBase
    from flext_auth._registry.lookup import FlextAuthRegistryLookup
    from flext_auth._registry.mutation import FlextAuthRegistryMutation
    from flext_auth._registry.plugins import FlextAuthRegistryPlugins


__all__: tuple[str, ...] = (
    "FlextAuthRegistryBase",
    "FlextAuthRegistryLookup",
    "FlextAuthRegistryMutation",
    "FlextAuthRegistryPlugins",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthRegistryBase": ".base",
        "FlextAuthRegistryLookup": ".lookup",
        "FlextAuthRegistryMutation": ".mutation",
        "FlextAuthRegistryPlugins": ".plugins",
    }),
    public_exports=__all__,
)

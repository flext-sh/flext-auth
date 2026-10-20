# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Registry package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._registry.base import FlextAuthRegistryBase
    from flext_auth._registry.lookup import FlextAuthRegistryLookup
    from flext_auth._registry.mutation import FlextAuthRegistryMutation


__all__: tuple[str, ...] = (
    "FlextAuthRegistryBase",
    "FlextAuthRegistryLookup",
    "FlextAuthRegistryMutation",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthRegistryBase": ".base",
        "FlextAuthRegistryLookup": ".lookup",
        "FlextAuthRegistryMutation": ".mutation",
    }),
    public_exports=__all__,
)

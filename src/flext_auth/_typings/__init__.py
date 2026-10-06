# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Typings package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._typings.auth import FlextAuthTypesAuth
    from flext_auth._typings.base import FlextAuthTypesBase


__all__: tuple[str, ...] = ("FlextAuthTypesAuth", "FlextAuthTypesBase")

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({"FlextAuthTypesAuth": ".auth", "FlextAuthTypesBase": ".base"}),
    public_exports=__all__,
)

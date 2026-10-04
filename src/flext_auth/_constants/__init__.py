# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Constants package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._constants.auth import FlextAuthConstantsAuth
    from flext_auth._constants.auth_claims import FlextAuthConstantsAuthClaims
    from flext_auth._constants.auth_enums import FlextAuthConstantsAuthEnums
    from flext_auth._constants.auth_security import FlextAuthConstantsAuthSecurity
    from flext_auth._constants.auth_values import FlextAuthConstantsAuthValues
    from flext_auth._constants.base import FlextAuthConstantsBase


__all__: tuple[str, ...] = (
    "FlextAuthConstantsAuth",
    "FlextAuthConstantsAuthClaims",
    "FlextAuthConstantsAuthEnums",
    "FlextAuthConstantsAuthSecurity",
    "FlextAuthConstantsAuthValues",
    "FlextAuthConstantsBase",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth": ("FlextAuthConstantsAuth",),
            ".auth_claims": ("FlextAuthConstantsAuthClaims",),
            ".auth_enums": ("FlextAuthConstantsAuthEnums",),
            ".auth_security": ("FlextAuthConstantsAuthSecurity",),
            ".auth_values": ("FlextAuthConstantsAuthValues",),
            ".base": ("FlextAuthConstantsBase",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

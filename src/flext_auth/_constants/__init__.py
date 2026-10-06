# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Constants package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

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

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthConstantsAuth": ".auth",
        "FlextAuthConstantsAuthClaims": ".auth_claims",
        "FlextAuthConstantsAuthEnums": ".auth_enums",
        "FlextAuthConstantsAuthSecurity": ".auth_security",
        "FlextAuthConstantsAuthValues": ".auth_values",
        "FlextAuthConstantsBase": ".base",
    }),
    public_exports=__all__,
)

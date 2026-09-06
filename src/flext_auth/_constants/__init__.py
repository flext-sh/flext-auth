# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Constants package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth import FlextAuthConstantsAuth
    from .auth_claims import FlextAuthConstantsAuthClaims
    from .auth_enums import FlextAuthConstantsAuthEnums
    from .auth_security import FlextAuthConstantsAuthSecurity
    from .auth_values import FlextAuthConstantsAuthValues
__all__: tuple[str, ...] = (
    "FlextAuthConstantsAuth",
    "FlextAuthConstantsAuthClaims",
    "FlextAuthConstantsAuthEnums",
    "FlextAuthConstantsAuthSecurity",
    "FlextAuthConstantsAuthValues",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth": ("FlextAuthConstantsAuth",),
            ".auth_claims": ("FlextAuthConstantsAuthClaims",),
            ".auth_enums": ("FlextAuthConstantsAuthEnums",),
            ".auth_security": ("FlextAuthConstantsAuthSecurity",),
            ".auth_values": ("FlextAuthConstantsAuthValues",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

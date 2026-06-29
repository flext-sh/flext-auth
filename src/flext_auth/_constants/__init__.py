# AUTO-GENERATED FILE — Regenerate with: make gen
"""Constants package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".auth": ("FlextAuthConstantsAuth",),
        ".auth_claims": ("FlextAuthConstantsAuthClaims",),
        ".auth_enums": ("FlextAuthConstantsAuthEnums",),
        ".auth_security": ("FlextAuthConstantsAuthSecurity",),
        ".auth_values": ("FlextAuthConstantsAuthValues",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

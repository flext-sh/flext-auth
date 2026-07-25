# AUTO-GENERATED FILE — Regenerate with: make gen
"""Constants package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._constants.auth import (
        FlextAuthConstantsAuth as FlextAuthConstantsAuth,
    )
    from flext_auth._constants.auth_claims import (
        FlextAuthConstantsAuthClaims as FlextAuthConstantsAuthClaims,
    )
    from flext_auth._constants.auth_enums import (
        FlextAuthConstantsAuthEnums as FlextAuthConstantsAuthEnums,
    )
    from flext_auth._constants.auth_security import (
        FlextAuthConstantsAuthSecurity as FlextAuthConstantsAuthSecurity,
    )
    from flext_auth._constants.auth_values import (
        FlextAuthConstantsAuthValues as FlextAuthConstantsAuthValues,
    )
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

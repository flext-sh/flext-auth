# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.services.auth_service import (
        FlextAuthApplicationService as FlextAuthApplicationService,
    )
    from flext_auth.services.identity_service import (
        FlextAuthIdentityService as FlextAuthIdentityService,
    )
    from flext_auth.services.provider_service import (
        FlextAuthProviderService as FlextAuthProviderService,
    )
    from flext_auth.services.session_service import (
        FlextAuthSessionService as FlextAuthSessionService,
    )
    from flext_auth.services.token_service import (
        FlextAuthTokenService as FlextAuthTokenService,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".auth_service": ("FlextAuthApplicationService",),
        ".identity_service": ("FlextAuthIdentityService",),
        ".provider_service": ("FlextAuthProviderService",),
        ".session_service": ("FlextAuthSessionService",),
        ".token_service": ("FlextAuthTokenService",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

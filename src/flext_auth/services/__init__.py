# AUTO-GENERATED FILE — Regenerate with: make gen
"""Services package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".identity_service": ("FlextAuthIdentityService",),
        ".middleware": ("FlextAuthMiddleware",),
        ".provider_service": ("FlextAuthProviderService",),
        ".session_service": ("FlextAuthSessionService",),
        ".token_service": ("FlextAuthTokenService",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)

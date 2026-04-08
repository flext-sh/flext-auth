# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextAuthIdentityService": ".identity_service",
    "FlextAuthManagers": ".managers",
    "FlextAuthMiddleware": ".middleware",
    "FlextAuthMixins": ".mixins",
    "FlextAuthProviderService": ".provider_service",
    "FlextAuthQuickstart": ".quickstart",
    "FlextAuthRegistry": ".registry",
    "FlextAuthServiceManagers": ".managers",
    "FlextAuthSessionService": ".session_service",
    "FlextAuthTokenService": ".token_service",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)

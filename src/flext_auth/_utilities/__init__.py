# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextAuthIdentityService": (
        "flext_auth._utilities.identity_service",
        "FlextAuthIdentityService",
    ),
    "FlextAuthManagers": ("flext_auth._utilities.managers", "FlextAuthManagers"),
    "FlextAuthMiddleware": ("flext_auth._utilities.middleware", "FlextAuthMiddleware"),
    "FlextAuthMixins": ("flext_auth._utilities.mixins", "FlextAuthMixins"),
    "FlextAuthProviderService": (
        "flext_auth._utilities.provider_service",
        "FlextAuthProviderService",
    ),
    "FlextAuthQuickstart": ("flext_auth._utilities.quickstart", "FlextAuthQuickstart"),
    "FlextAuthRegistry": ("flext_auth._utilities.registry", "FlextAuthRegistry"),
    "FlextAuthServiceManagers": (
        "flext_auth._utilities.managers",
        "FlextAuthServiceManagers",
    ),
    "FlextAuthSessionService": (
        "flext_auth._utilities.session_service",
        "FlextAuthSessionService",
    ),
    "FlextAuthTokenService": (
        "flext_auth._utilities.token_service",
        "FlextAuthTokenService",
    ),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)

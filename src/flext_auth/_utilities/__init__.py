# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_auth._utilities.identity_service as _flext_auth__utilities_identity_service

    identity_service = _flext_auth__utilities_identity_service
    import flext_auth._utilities.managers as _flext_auth__utilities_managers
    from flext_auth._utilities.identity_service import FlextAuthIdentityService

    managers = _flext_auth__utilities_managers
    import flext_auth._utilities.middleware as _flext_auth__utilities_middleware
    from flext_auth._utilities.managers import (
        FlextAuthManagers,
        FlextAuthServiceManagers,
    )

    middleware = _flext_auth__utilities_middleware
    import flext_auth._utilities.mixins as _flext_auth__utilities_mixins
    from flext_auth._utilities.middleware import FlextAuthMiddleware

    mixins = _flext_auth__utilities_mixins
    import flext_auth._utilities.provider_service as _flext_auth__utilities_provider_service
    from flext_auth._utilities.mixins import FlextAuthMixins

    provider_service = _flext_auth__utilities_provider_service
    import flext_auth._utilities.quickstart as _flext_auth__utilities_quickstart
    from flext_auth._utilities.provider_service import FlextAuthProviderService

    quickstart = _flext_auth__utilities_quickstart
    import flext_auth._utilities.registry as _flext_auth__utilities_registry
    from flext_auth._utilities.quickstart import FlextAuthQuickstart

    registry = _flext_auth__utilities_registry
    import flext_auth._utilities.session_service as _flext_auth__utilities_session_service
    from flext_auth._utilities.registry import FlextAuthRegistry

    session_service = _flext_auth__utilities_session_service
    import flext_auth._utilities.token_service as _flext_auth__utilities_token_service
    from flext_auth._utilities.session_service import FlextAuthSessionService

    token_service = _flext_auth__utilities_token_service
    from flext_auth._utilities.token_service import FlextAuthTokenService
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
    "identity_service": "flext_auth._utilities.identity_service",
    "managers": "flext_auth._utilities.managers",
    "middleware": "flext_auth._utilities.middleware",
    "mixins": "flext_auth._utilities.mixins",
    "provider_service": "flext_auth._utilities.provider_service",
    "quickstart": "flext_auth._utilities.quickstart",
    "registry": "flext_auth._utilities.registry",
    "session_service": "flext_auth._utilities.session_service",
    "token_service": "flext_auth._utilities.token_service",
}

__all__ = [
    "FlextAuthIdentityService",
    "FlextAuthManagers",
    "FlextAuthMiddleware",
    "FlextAuthMixins",
    "FlextAuthProviderService",
    "FlextAuthQuickstart",
    "FlextAuthRegistry",
    "FlextAuthServiceManagers",
    "FlextAuthSessionService",
    "FlextAuthTokenService",
    "identity_service",
    "managers",
    "middleware",
    "mixins",
    "provider_service",
    "quickstart",
    "registry",
    "session_service",
    "token_service",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

import typing as _t

from flext_auth._utilities.identity_service import FlextAuthIdentityService
from flext_auth._utilities.managers import (
    FlextAuthManagers,
    FlextAuthServiceManagers,
)
from flext_auth._utilities.middleware import FlextAuthMiddleware
from flext_auth._utilities.mixins import FlextAuthMixins
from flext_auth._utilities.provider_service import FlextAuthProviderService
from flext_auth._utilities.quickstart import FlextAuthQuickstart
from flext_auth._utilities.registry import FlextAuthRegistry
from flext_auth._utilities.session_service import FlextAuthSessionService
from flext_auth._utilities.token_service import FlextAuthTokenService
from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_auth._utilities.identity_service as _flext_auth__utilities_identity_service

    identity_service = _flext_auth__utilities_identity_service
    import flext_auth._utilities.managers as _flext_auth__utilities_managers

    managers = _flext_auth__utilities_managers
    import flext_auth._utilities.middleware as _flext_auth__utilities_middleware

    middleware = _flext_auth__utilities_middleware
    import flext_auth._utilities.mixins as _flext_auth__utilities_mixins

    mixins = _flext_auth__utilities_mixins
    import flext_auth._utilities.provider_service as _flext_auth__utilities_provider_service

    provider_service = _flext_auth__utilities_provider_service
    import flext_auth._utilities.quickstart as _flext_auth__utilities_quickstart

    quickstart = _flext_auth__utilities_quickstart
    import flext_auth._utilities.registry as _flext_auth__utilities_registry

    registry = _flext_auth__utilities_registry
    import flext_auth._utilities.session_service as _flext_auth__utilities_session_service

    session_service = _flext_auth__utilities_session_service
    import flext_auth._utilities.token_service as _flext_auth__utilities_token_service

    token_service = _flext_auth__utilities_token_service

    _ = (
        FlextAuthIdentityService,
        FlextAuthManagers,
        FlextAuthMiddleware,
        FlextAuthMixins,
        FlextAuthProviderService,
        FlextAuthQuickstart,
        FlextAuthRegistry,
        FlextAuthServiceManagers,
        FlextAuthSessionService,
        FlextAuthTokenService,
        identity_service,
        managers,
        middleware,
        mixins,
        provider_service,
        quickstart,
        registry,
        session_service,
        token_service,
    )
_LAZY_IMPORTS = {
    "FlextAuthIdentityService": "flext_auth._utilities.identity_service",
    "FlextAuthManagers": "flext_auth._utilities.managers",
    "FlextAuthMiddleware": "flext_auth._utilities.middleware",
    "FlextAuthMixins": "flext_auth._utilities.mixins",
    "FlextAuthProviderService": "flext_auth._utilities.provider_service",
    "FlextAuthQuickstart": "flext_auth._utilities.quickstart",
    "FlextAuthRegistry": "flext_auth._utilities.registry",
    "FlextAuthServiceManagers": "flext_auth._utilities.managers",
    "FlextAuthSessionService": "flext_auth._utilities.session_service",
    "FlextAuthTokenService": "flext_auth._utilities.token_service",
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

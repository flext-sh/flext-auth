# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Utilities package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_auth._utilities import (
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
    from flext_core import FlextTypes

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

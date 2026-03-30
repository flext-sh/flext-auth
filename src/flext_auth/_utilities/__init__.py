# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Flext auth utilities subpackage."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._utilities import (
        identity_service as identity_service,
        managers as managers,
        middleware as middleware,
        mixins as mixins,
        provider_service as provider_service,
        quickstart as quickstart,
        registry as registry,
        session_service as session_service,
        token_service as token_service,
    )
    from flext_auth._utilities.identity_service import (
        FlextAuthIdentityService as FlextAuthIdentityService,
    )
    from flext_auth._utilities.managers import (
        FlextAuthManagers as FlextAuthManagers,
        FlextAuthServiceManagers as FlextAuthServiceManagers,
    )
    from flext_auth._utilities.middleware import (
        FlextAuthMiddleware as FlextAuthMiddleware,
    )
    from flext_auth._utilities.mixins import FlextAuthMixins as FlextAuthMixins
    from flext_auth._utilities.provider_service import (
        FlextAuthProviderService as FlextAuthProviderService,
    )
    from flext_auth._utilities.quickstart import (
        FlextAuthQuickstart as FlextAuthQuickstart,
    )
    from flext_auth._utilities.registry import FlextAuthRegistry as FlextAuthRegistry
    from flext_auth._utilities.session_service import (
        FlextAuthSessionService as FlextAuthSessionService,
    )
    from flext_auth._utilities.token_service import (
        FlextAuthTokenService as FlextAuthTokenService,
    )

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextAuthIdentityService": [
        "flext_auth._utilities.identity_service",
        "FlextAuthIdentityService",
    ],
    "FlextAuthManagers": ["flext_auth._utilities.managers", "FlextAuthManagers"],
    "FlextAuthMiddleware": ["flext_auth._utilities.middleware", "FlextAuthMiddleware"],
    "FlextAuthMixins": ["flext_auth._utilities.mixins", "FlextAuthMixins"],
    "FlextAuthProviderService": [
        "flext_auth._utilities.provider_service",
        "FlextAuthProviderService",
    ],
    "FlextAuthQuickstart": ["flext_auth._utilities.quickstart", "FlextAuthQuickstart"],
    "FlextAuthRegistry": ["flext_auth._utilities.registry", "FlextAuthRegistry"],
    "FlextAuthServiceManagers": [
        "flext_auth._utilities.managers",
        "FlextAuthServiceManagers",
    ],
    "FlextAuthSessionService": [
        "flext_auth._utilities.session_service",
        "FlextAuthSessionService",
    ],
    "FlextAuthTokenService": [
        "flext_auth._utilities.token_service",
        "FlextAuthTokenService",
    ],
    "identity_service": ["flext_auth._utilities.identity_service", ""],
    "managers": ["flext_auth._utilities.managers", ""],
    "middleware": ["flext_auth._utilities.middleware", ""],
    "mixins": ["flext_auth._utilities.mixins", ""],
    "provider_service": ["flext_auth._utilities.provider_service", ""],
    "quickstart": ["flext_auth._utilities.quickstart", ""],
    "registry": ["flext_auth._utilities.registry", ""],
    "session_service": ["flext_auth._utilities.session_service", ""],
    "token_service": ["flext_auth._utilities.token_service", ""],
}

_EXPORTS: Sequence[str] = [
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)

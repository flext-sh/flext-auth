# AUTO-GENERATED FILE — Regenerate with: make gen
"""Protocols package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._protocols.auth import (
        FlextAuthProtocolsAuth as FlextAuthProtocolsAuth,
    )
    from flext_auth._protocols.auth_identity import (
        FlextAuthProtocolsAuthIdentity as FlextAuthProtocolsAuthIdentity,
    )
    from flext_auth._protocols.auth_provider import (
        FlextAuthProtocolsAuthProvider as FlextAuthProtocolsAuthProvider,
    )
    from flext_auth._protocols.auth_service import (
        FlextAuthProtocolsAuthService as FlextAuthProtocolsAuthService,
    )
    from flext_auth._protocols.auth_session import (
        FlextAuthProtocolsAuthSession as FlextAuthProtocolsAuthSession,
    )
    from flext_auth._protocols.auth_token import (
        FlextAuthProtocolsAuthToken as FlextAuthProtocolsAuthToken,
    )
    from flext_auth._protocols.auth_transport import (
        FlextAuthProtocolsAuthTransport as FlextAuthProtocolsAuthTransport,
    )
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".auth": ("FlextAuthProtocolsAuth",),
        ".auth_identity": ("FlextAuthProtocolsAuthIdentity",),
        ".auth_provider": ("FlextAuthProtocolsAuthProvider",),
        ".auth_service": ("FlextAuthProtocolsAuthService",),
        ".auth_session": ("FlextAuthProtocolsAuthSession",),
        ".auth_token": ("FlextAuthProtocolsAuthToken",),
        ".auth_transport": ("FlextAuthProtocolsAuthTransport",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

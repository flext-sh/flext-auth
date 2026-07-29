# @generated AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Protocols package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth import FlextAuthProtocolsAuth as FlextAuthProtocolsAuth
    from .auth_identity import (
        FlextAuthProtocolsAuthIdentity as FlextAuthProtocolsAuthIdentity,
    )
    from .auth_provider import (
        FlextAuthProtocolsAuthProvider as FlextAuthProtocolsAuthProvider,
    )
    from .auth_service import (
        FlextAuthProtocolsAuthService as FlextAuthProtocolsAuthService,
    )
    from .auth_session import (
        FlextAuthProtocolsAuthSession as FlextAuthProtocolsAuthSession,
    )
    from .auth_token import FlextAuthProtocolsAuthToken as FlextAuthProtocolsAuthToken
    from .auth_transport import (
        FlextAuthProtocolsAuthTransport as FlextAuthProtocolsAuthTransport,
    )

_LAZY_MODULES: dict[str, tuple[str, ...]] = {
    ".auth": ("FlextAuthProtocolsAuth",),
    ".auth_identity": ("FlextAuthProtocolsAuthIdentity",),
    ".auth_provider": ("FlextAuthProtocolsAuthProvider",),
    ".auth_service": ("FlextAuthProtocolsAuthService",),
    ".auth_session": ("FlextAuthProtocolsAuthSession",),
    ".auth_token": ("FlextAuthProtocolsAuthToken",),
    ".auth_transport": ("FlextAuthProtocolsAuthTransport",),
}


_LAZY_ALIAS_GROUPS: dict[str, tuple[tuple[str, str], ...]] = {}


_LAZY_IMPORTS = build_lazy_import_map(
    _LAZY_MODULES, alias_groups=_LAZY_ALIAS_GROUPS, sort_keys=False
)

_PUBLIC_EXPORTS: tuple[str, ...] = (
    "FlextAuthProtocolsAuth",
    "FlextAuthProtocolsAuthIdentity",
    "FlextAuthProtocolsAuthProvider",
    "FlextAuthProtocolsAuthService",
    "FlextAuthProtocolsAuthSession",
    "FlextAuthProtocolsAuthToken",
    "FlextAuthProtocolsAuthTransport",
)

__all__: tuple[str, ...] = tuple(_PUBLIC_EXPORTS)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Protocols package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from .auth import FlextAuthProtocolsAuth
    from .auth_identity import FlextAuthProtocolsAuthIdentity
    from .auth_provider import FlextAuthProtocolsAuthProvider
    from .auth_service import FlextAuthProtocolsAuthService
    from .auth_session import FlextAuthProtocolsAuthSession
    from .auth_token import FlextAuthProtocolsAuthToken
    from .auth_transport import FlextAuthProtocolsAuthTransport
__all__: tuple[str, ...] = (
    "FlextAuthProtocolsAuth",
    "FlextAuthProtocolsAuthIdentity",
    "FlextAuthProtocolsAuthProvider",
    "FlextAuthProtocolsAuthService",
    "FlextAuthProtocolsAuthSession",
    "FlextAuthProtocolsAuthToken",
    "FlextAuthProtocolsAuthTransport",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".auth": ("FlextAuthProtocolsAuth",),
            ".auth_identity": ("FlextAuthProtocolsAuthIdentity",),
            ".auth_provider": ("FlextAuthProtocolsAuthProvider",),
            ".auth_service": ("FlextAuthProtocolsAuthService",),
            ".auth_session": ("FlextAuthProtocolsAuthSession",),
            ".auth_token": ("FlextAuthProtocolsAuthToken",),
            ".auth_transport": ("FlextAuthProtocolsAuthTransport",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._protocols.auth import FlextAuthProtocolsAuth
    from flext_auth._protocols.auth_identity import FlextAuthProtocolsAuthIdentity
    from flext_auth._protocols.auth_provider import FlextAuthProtocolsAuthProvider
    from flext_auth._protocols.auth_service import FlextAuthProtocolsAuthService
    from flext_auth._protocols.auth_session import FlextAuthProtocolsAuthSession
    from flext_auth._protocols.auth_token import FlextAuthProtocolsAuthToken
    from flext_auth._protocols.auth_transport import FlextAuthProtocolsAuthTransport
    from flext_auth._protocols.base import FlextAuthProtocolsBase


__all__: tuple[str, ...] = (
    "FlextAuthProtocolsAuth",
    "FlextAuthProtocolsAuthIdentity",
    "FlextAuthProtocolsAuthProvider",
    "FlextAuthProtocolsAuthService",
    "FlextAuthProtocolsAuthSession",
    "FlextAuthProtocolsAuthToken",
    "FlextAuthProtocolsAuthTransport",
    "FlextAuthProtocolsBase",
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
            ".base": ("FlextAuthProtocolsBase",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

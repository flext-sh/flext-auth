# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._protocols.auth import FlextAuthProtocolsAuth
    from flext_auth._protocols.auth_identity import FlextAuthProtocolsAuthIdentity
    from flext_auth._protocols.auth_provider import FlextAuthProtocolsAuthProvider
    from flext_auth._protocols.auth_service import FlextAuthProtocolsAuthService
    from flext_auth._protocols.auth_session import FlextAuthProtocolsAuthSession
    from flext_auth._protocols.auth_transport import FlextAuthProtocolsAuthTransport
    from flext_auth._protocols.base import FlextAuthProtocolsBase


__all__: tuple[str, ...] = (
    "FlextAuthProtocolsAuth",
    "FlextAuthProtocolsAuthIdentity",
    "FlextAuthProtocolsAuthProvider",
    "FlextAuthProtocolsAuthService",
    "FlextAuthProtocolsAuthSession",
    "FlextAuthProtocolsAuthTransport",
    "FlextAuthProtocolsBase",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthProtocolsAuth": ".auth",
        "FlextAuthProtocolsAuthIdentity": ".auth_identity",
        "FlextAuthProtocolsAuthProvider": ".auth_provider",
        "FlextAuthProtocolsAuthService": ".auth_service",
        "FlextAuthProtocolsAuthSession": ".auth_session",
        "FlextAuthProtocolsAuthSession": ".auth_session",
        "FlextAuthProtocolsAuthTransport": ".auth_transport",
        "FlextAuthProtocolsBase": ".base",
    }),
    public_exports=__all__,
)

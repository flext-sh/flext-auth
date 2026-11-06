# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Protocols package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._protocols.auth import FlextAuthProtocolsAuth
    from flext_auth._protocols.auth_identity import FlextAuthProtocolsAuthIdentity
    from flext_auth._protocols.auth_identity_request import (
        FlextAuthProtocolsAuthIdentityRequest,
    )
    from flext_auth._protocols.auth_provider import FlextAuthProtocolsAuthProvider
    from flext_auth._protocols.auth_provider_config import (
        FlextAuthProtocolsAuthProviderConfig,
    )
    from flext_auth._protocols.auth_response import FlextAuthProtocolsAuthResponse
    from flext_auth._protocols.auth_service import FlextAuthProtocolsAuthService
    from flext_auth._protocols.auth_session import FlextAuthProtocolsAuthSession
    from flext_auth._protocols.auth_transport import FlextAuthProtocolsAuthTransport
    from flext_auth._protocols.auth_user_identity_extras import (
        FlextAuthProtocolsAuthUserIdentityExtras,
    )
    from flext_auth._protocols.base import FlextAuthProtocolsBase


__all__: tuple[str, ...] = (
    "FlextAuthProtocolsAuth",
    "FlextAuthProtocolsAuthIdentity",
    "FlextAuthProtocolsAuthIdentityRequest",
    "FlextAuthProtocolsAuthProvider",
    "FlextAuthProtocolsAuthProviderConfig",
    "FlextAuthProtocolsAuthResponse",
    "FlextAuthProtocolsAuthService",
    "FlextAuthProtocolsAuthSession",
    "FlextAuthProtocolsAuthTransport",
    "FlextAuthProtocolsAuthUserIdentityExtras",
    "FlextAuthProtocolsBase",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextAuthProtocolsAuth": ".auth",
        "FlextAuthProtocolsAuthIdentity": ".auth_identity",
        "FlextAuthProtocolsAuthIdentityRequest": ".auth_identity_request",
        "FlextAuthProtocolsAuthProvider": ".auth_provider",
        "FlextAuthProtocolsAuthProviderConfig": ".auth_provider_config",
        "FlextAuthProtocolsAuthResponse": ".auth_response",
        "FlextAuthProtocolsAuthService": ".auth_service",
        "FlextAuthProtocolsAuthSession": ".auth_session",
        "FlextAuthProtocolsAuthTransport": ".auth_transport",
        "FlextAuthProtocolsAuthUserIdentityExtras": ".auth_user_identity_extras",
        "FlextAuthProtocolsBase": ".base",
    },
    public_exports=__all__,
)

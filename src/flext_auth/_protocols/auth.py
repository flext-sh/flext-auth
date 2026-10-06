"""Authentication protocol namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._protocols.auth_identity import FlextAuthProtocolsAuthIdentity
from flext_auth._protocols.auth_provider import FlextAuthProtocolsAuthProvider
from flext_auth._protocols.auth_service import FlextAuthProtocolsAuthService
from flext_auth._protocols.auth_session import FlextAuthProtocolsAuthSession
from flext_auth._protocols.auth_session import FlextAuthProtocolsAuthSession
from flext_auth._protocols.auth_transport import FlextAuthProtocolsAuthTransport


class FlextAuthProtocolsAuth(
    FlextAuthProtocolsAuthIdentity,
    FlextAuthProtocolsAuthSession,
    FlextAuthProtocolsAuthSession,
    FlextAuthProtocolsAuthService,
    FlextAuthProtocolsAuthProvider,
    FlextAuthProtocolsAuthTransport,
):
    """Authentication protocol namespace assembled from focused contracts."""


__all__: list[str] = ["FlextAuthProtocolsAuth"]

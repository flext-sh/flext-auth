"""Authentication protocol namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._protocols import (
    FlextAuthProtocolsAuthIdentity,
    FlextAuthProtocolsAuthProvider,
    FlextAuthProtocolsAuthService,
    FlextAuthProtocolsAuthSession,
    FlextAuthProtocolsAuthTransport,
)


class FlextAuthProtocolsAuth(
    FlextAuthProtocolsAuthIdentity,
    FlextAuthProtocolsAuthSession,
    FlextAuthProtocolsAuthService,
    FlextAuthProtocolsAuthProvider,
    FlextAuthProtocolsAuthTransport,
):
    """Authentication protocol namespace assembled from focused contracts."""


__all__: list[str] = ["FlextAuthProtocolsAuth"]

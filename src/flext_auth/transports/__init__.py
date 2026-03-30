# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT Auth Transports - Transport layer adapters.

This package contains transport adapters that enable authentication over
different communication protocols (HTTP, gRPC, WebSocket, etc.).

MANDATORY: HTTP transport MUST use flext-api, gRPC transport MUST use flext-grpc.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.transports import base, http
    from flext_auth.transports.http import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextWebTransportAdapter": "flext_auth.transports.http",
    "base": "flext_auth.transports.base",
    "http": "flext_auth.transports.http",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, sorted(_LAZY_IMPORTS))

"""FLEXT Auth Transports - Transport layer adapters.

This package contains transport adapters that enable authentication over
different communication protocols (HTTP, gRPC, WebSocket, etc.).

MANDATORY: HTTP transport MUST use flext-api, gRPC transport MUST use flext-grpc.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.transports.base import BaseTransportAdapter
from flext_auth.transports.http import HttpTransportAdapter
from flext_core import FlextTypes

__all__: FlextTypes.StringList = [
    "BaseTransportAdapter",
    "HttpTransportAdapter",
]

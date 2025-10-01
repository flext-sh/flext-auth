"""FLEXT Auth Transports - Transport layer adapters.

This package contains transport adapters that enable authentication over
different communication protocols (HTTP, gRPC, WebSocket, etc.).

MANDATORY: HTTP transport MUST use flext-api, gRPC transport MUST use flext-grpc.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

# Base transport protocol will be imported once created
# from flext_auth.transports.base import BaseTransportAdapter

__all__: list[str] = [
    # Will be populated as transports are implemented
    # "BaseTransportAdapter",
    # "HttpTransportAdapter",
    # "GrpcTransportAdapter",
    # etc.
]

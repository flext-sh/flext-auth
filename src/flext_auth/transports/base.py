"""Base transport adapter protocol for FLEXT Auth.

This module defines the base protocol that all transport adapters must implement,
enabling authentication over different communication protocols (HTTP, gRPC, WebSocket, etc.).

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import Protocol

from flext_core import r


class BaseTransportAdapter(Protocol):
    """Protocol for transport adapters.

    Transport adapters enable authentication operations over different
    communication protocols (HTTP, gRPC, WebSocket, etc.).

    All transport implementations must implement this protocol to ensure
    consistent interface across different transport mechanisms.

    Example:
        >>> class FlextWebTransportAdapter(BaseTransportAdapter):
        ...     def send_request(
        ...         self,
        ...         url: str,
        ...         method: str = "POST",
        ...         data: dict[str, object] | None = None,
        ...         headers: dict[str, str] | None = None,
        ...     ) -> r[dict[str, object]]:
        ...         # HTTP-specific implementation
        ...         pass

    """

    def send_request(
        self,
        url: str,
        method: str = "POST",
        data: dict[str, object] | None = None,
        headers: dict[str, str] | None = None,
        **kwargs: object,
    ) -> r[dict[str, object]]:
        """Send a request using this transport.

        Args:
        url: Target URL or endpoint
        method: HTTP method or operation type
        data: Request payload data
        headers: Request headers or metadata
        **kwargs: Transport-specific additional parameters

        Returns:
        FlextResult containing response data or error

        """
        ...

    def get_transport_type(self) -> str:
        """Get the transport type identifier.

        Returns:
            str: Transport type (e.g., "http", "grpc", "websocket")

        """
        ...


__all__ = [
    "BaseTransportAdapter",
]

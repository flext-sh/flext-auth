"""Authentication transport protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from flext_api import p

    from flext_auth import t


class FlextAuthProtocolsAuthTransport:
    @runtime_checkable
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
            ...         data: t.ConfigurationMapping | None = None,
            ...         headers: t.StrMapping | None = None,
            ...     ) -> p.Result[t.ConfigurationMapping]:
            ...         # HTTP-specific implementation
            ...         pass

        """

        def get_transport_type(self) -> str:
            """Get the transport type identifier.

            Returns:
                str: Transport type (e.g., "http", "grpc", "websocket")

            """
            ...

        def send_request(
            self,
            url: str,
            method: str = "POST",
            data: t.ConfigurationMapping | None = None,
            headers: t.StrMapping | None = None,
            **kwargs: t.Scalar,
        ) -> p.Result[t.ConfigurationMapping]:
            """Send a request using this transport.

            Args:
            url: Target URL or endpoint
            method: HTTP method or operation type
            data: Request payload data
            headers: Request headers or metadata
            **kwargs: Transport-specific additional parameters

            Returns:
            r containing response data or error

            """
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthTransport"]

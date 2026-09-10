"""Authentication protocol namespace."""

from __future__ import annotations

from .auth_identity import FlextAuthProtocolsAuthIdentity
from .auth_provider import FlextAuthProtocolsAuthProvider
from .auth_service import FlextAuthProtocolsAuthService
from .auth_session import FlextAuthProtocolsAuthSession
from .auth_token import FlextAuthProtocolsAuthToken
from .auth_transport import FlextAuthProtocolsAuthTransport


class FlextAuthProtocolsAuth(
    FlextAuthProtocolsAuthIdentity,
    FlextAuthProtocolsAuthSession,
    FlextAuthProtocolsAuthToken,
    FlextAuthProtocolsAuthService,
    FlextAuthProtocolsAuthProvider,
    FlextAuthProtocolsAuthTransport,
):
    """Authentication protocol namespace assembled from focused contracts."""


__all__: list[str] = ["FlextAuthProtocolsAuth"]

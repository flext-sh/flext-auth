"""FLEXT Auth protocols facade."""

from __future__ import annotations

from flext_api import p

from ._protocols.auth import FlextAuthProtocolsAuth
from ._protocols.base import FlextAuthProtocolsBase


class FlextAuthProtocols(p):
    """Unified authentication protocols following FLEXT domain extension pattern."""

    class Auth(FlextAuthProtocolsBase, FlextAuthProtocolsAuth):
        """Authentication domain-specific protocols."""


p = FlextAuthProtocols

__all__: list[str] = ["FlextAuthProtocols", "p"]

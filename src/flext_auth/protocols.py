"""FLEXT Auth protocols facade."""

from __future__ import annotations

from flext_api import p

from flext_auth._protocols.auth import FlextAuthProtocolsAuth


class FlextAuthProtocols(p):
    """Unified authentication protocols following FLEXT domain extension pattern."""

    class Auth(FlextAuthProtocolsAuth):
        """Authentication domain-specific protocols."""


p = FlextAuthProtocols

__all__: list[str] = ["FlextAuthProtocols", "p"]

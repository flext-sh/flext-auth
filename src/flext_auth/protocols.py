"""FLEXT Auth protocols facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import FlextApiProtocols

from flext_auth._protocols.auth import FlextAuthProtocolsAuth
from flext_auth._protocols.base import FlextAuthProtocolsBase


class FlextAuthProtocols(FlextApiProtocols):
    """Unified authentication protocols following FLEXT domain extension pattern."""

    class Auth(FlextAuthProtocolsBase, FlextAuthProtocolsAuth):
        """Authentication domain-specific protocols."""


p = FlextAuthProtocols

__all__: list[str] = ["FlextAuthProtocols", "p"]

"""FLEXT Auth Session Service - Focused session management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import override

from flext_auth import FlextAuthSettings, FlextAuthUtilitiesManagers, p, u
from flext_core import r, s


class FlextAuthSessionService(s):
    """Focused service for session management with complete flext-core integration."""

    def __init__(self, settings: FlextAuthSettings, dispatcher: p.Dispatcher) -> None:
        """Initialize session service with flext-core integration."""
        super().__init__()
        self._managers = FlextAuthUtilitiesManagers.ServiceManagers(
            settings, dispatcher
        )

    @property
    def session_manager(self) -> FlextAuthUtilitiesManagers.FlextAuthSessionManager:
        """Direct access to session manager for client orchestration."""
        return self._managers.session_manager

    def cleanup_expired_sessions(self) -> r[int]:
        """Railway-oriented cleanup of expired sessions from the system."""
        u.fetch_logger(__name__).info("Cleanup of expired sessions requested")
        return self.session_manager.cleanup_expired_sessions()

    @override
    def execute(self) -> r[bool]:
        """Execute method for s interface.

        Session service doesn't use generic execute pattern.
        Use specific session methods instead.
        """
        return r[bool].fail(
            "FlextAuthSessionService is focused - use session_manager property or cleanup_expired_sessions()",
        )


__all__: list[str] = ["FlextAuthSessionService"]

"""FLEXT Auth Session Service - Focused session management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth.managers import FlextAuthManagers, ServiceManagers
from flext_auth.settings import FlextAuthSettings
from flext_core import FlextLogger, FlextService as s, r
from flext_core.dispatcher import FlextDispatcher


class FlextAuthSessionService(s[object]):
    """Focused service for session management with complete flext-core integration."""

    def __init__(self, config: FlextAuthSettings, dispatcher: FlextDispatcher) -> None:
        """Initialize session service with flext-core integration."""
        super().__init__()
        self._managers = ServiceManagers(config, dispatcher)

    @property
    def session_manager(self) -> FlextAuthManagers.FlextAuthSessionManager:
        """Direct access to session manager for client orchestration."""
        return self._managers.session_manager

    @session_manager.setter
    def session_manager(self, value: FlextAuthManagers.FlextAuthSessionManager) -> None:
        """Set session manager (for service composition)."""
        self._managers.session_manager = value

    def execute(self) -> r[object]:
        """Execute method for FlextService interface.

        Session service doesn't use generic execute pattern.
        Use specific session methods instead.
        """
        return r[object].fail(
            "FlextAuthSessionService is focused - use session_manager property or cleanup_expired_sessions()",
        )

    def cleanup_expired_sessions(self) -> r[int]:
        """Railway-oriented cleanup of expired sessions from the system."""
        FlextLogger(__name__).info("Cleanup of expired sessions requested")
        return self.session_manager.cleanup_expired_sessions()


__all__ = ["FlextAuthSessionService"]

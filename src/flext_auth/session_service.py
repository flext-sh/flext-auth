"""FLEXT Auth Session Service - Focused session management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

# FLEXT Standard imports
from flext import FlextResult as r,
    FlextService as s
from flext_core.dispatcher import FlextDispatcher

from flext_auth.managers import (
    FlextAuthManagers,
    ServiceManagerMixin,
)
from flext_auth.settings import FlextAuthSettings


class FlextAuthSessionService(ServiceManagerMixin, s[object]):
    """Focused service for session management with complete flext-core integration."""

    def __init__(self, config: FlextAuthSettings, dispatcher: FlextDispatcher) -> None:
        """Initialize session service with flext-core integration."""
        super().__init__()
        self.init_managers(config, dispatcher)

    @property
    def session_manager(self) -> FlextAuthManagers.FlextAuthSessionManager:
        """Direct access to session manager for client orchestration."""
        return self._session_manager

    @session_manager.setter
    def session_manager(self, value: FlextAuthManagers.FlextAuthSessionManager) -> None:
        """Set session manager (for service composition)."""
        self._session_manager = value

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
        self.logger.info("Cleanup of expired sessions requested")
        return self.session_manager.cleanup_expired_sessions()


__all__ = ["FlextAuthSessionService"]

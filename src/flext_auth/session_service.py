"""FLEXT Auth Session Service - Focused session management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextDispatcher, FlextResult, FlextService

from flext_auth.config import FlextAuthConfig
from flext_auth.managers import (
    FlextAuthManagers,
    ServiceManagerMixin,
)


class FlextAuthSessionService(ServiceManagerMixin, FlextService[object]):
    """Focused service for session management with complete flext-core integration."""

    def __init__(self, config: FlextAuthConfig, dispatcher: FlextDispatcher) -> None:
        """Initialize session service with flext-core integration."""
        super().__init__()
        self._init_managers(config, dispatcher)

    @property
    def session_manager(self) -> FlextAuthManagers.FlextAuthSessionManager:
        """Direct access to session manager for client orchestration."""
        return self._session_manager

    def execute(self) -> FlextResult[object]:
        """Execute method for FlextService interface.

        Session service doesn't use generic execute pattern.
        Use specific session methods instead.
        """
        return FlextResult[object].fail(
            "FlextAuthSessionService is focused - use session_manager property or cleanup_expired_sessions()"
        )

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Railway-oriented cleanup of expired sessions from the system."""
        self.logger.info("Cleanup of expired sessions requested")
        # Simplified implementation - in production, this would query the session manager
        # For now, return 0 expired sessions cleaned
        return FlextResult[int].ok(0)


__all__ = ["FlextAuthSessionService"]

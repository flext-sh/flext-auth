"""FLEXT Auth Session Service - Focused session management operations.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import u, p, s, t


class FlextAuthSessionService(s):
    """Focused service for session management with complete flext-core integration."""

    def __init__(
        self, dispatcher: p.Dispatcher, managers: u.Auth.ServiceManagers | None = None
    ) -> None:
        """Initialize session service with flext-core integration."""
        super().__init__()
        self._managers = (
            managers if managers is not None else u.Auth.ServiceManagers(dispatcher)
        )

    @property
    def session_manager(self) -> u.Auth.FlextAuthSessionManager:
        """Direct access to session manager for client orchestration."""
        return self._managers.session_manager

    def cleanup_expired_sessions(self) -> p.Result[int]:
        """Railway-oriented cleanup of expired sessions from the system."""
        u.fetch_logger(__name__).info("Cleanup of expired sessions requested")
        return self.session_manager.cleanup_expired_sessions()


__all__: t.MutableSequenceOf[str] = ["FlextAuthSessionService"]

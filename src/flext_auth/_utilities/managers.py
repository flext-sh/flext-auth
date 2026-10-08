"""FLEXT Auth manager namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth._utilities._managers.auth_managers_session import (
    FlextAuthSessionManagers,
)
from flext_auth._utilities._managers.rate_limiter import FlextAuthRateLimiterManagers
from flext_auth._utilities._managers.user import FlextAuthUserManagers
from flext_auth._utilities.base import FlextAuthUtilitiesBase

if TYPE_CHECKING:
    from flext_auth import p, t


class FlextAuthUtilitiesManagers(
    FlextAuthUtilitiesBase,
    FlextAuthSessionManagers,
    FlextAuthRateLimiterManagers,
    FlextAuthUserManagers,
):
    """Namespace class for all authentication managers following FLEXT patterns."""

    class ServiceManagers:
        """Manager composition helper for auth services."""

        __slots__ = ("dispatcher", "rate_limiter", "session_manager", "user_manager")

        def __init__(self, dispatcher: p.Dispatcher) -> None:
            """Initialize all standard managers used by services."""
            self.dispatcher = dispatcher
            self.user_manager = FlextAuthUtilitiesManagers.FlextAuthUserManager()
            self.session_manager = FlextAuthUtilitiesManagers.FlextAuthSessionManager()
            self.rate_limiter = FlextAuthUtilitiesManagers.FlextAuthRateLimiter(
                dispatcher,
            )


__all__: t.MutableSequenceOf[str] = ["FlextAuthUtilitiesManagers"]

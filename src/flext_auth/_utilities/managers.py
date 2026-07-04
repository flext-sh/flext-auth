"""FLEXT Auth manager namespace."""

from __future__ import annotations

from typing import TYPE_CHECKING, ClassVar

from flext_api import r

from flext_auth._utilities._managers.auth_managers_session import (
    FlextAuthSessionManagers,
)
from flext_auth._utilities._managers.rate_limiter import FlextAuthRateLimiterManagers
from flext_auth._utilities._managers.user import FlextAuthUserManagers
from flext_core import FlextContext

if TYPE_CHECKING:
    from flext_auth import p, t
    from flext_auth.settings import FlextAuthSettings


class FlextAuthUtilitiesManagers(
    FlextAuthSessionManagers,
    FlextAuthRateLimiterManagers,
    FlextAuthUserManagers,
):
    """Namespace class for all authentication managers following FLEXT patterns."""

    _context_type: ClassVar[p.ContextType] = FlextContext

    class ServiceManagers:
        """Manager composition helper for auth services."""

        __slots__ = (
            "dispatcher",
            "rate_limiter",
            "session_manager",
            "settings",
            "user_manager",
        )

        def __init__(
            self,
            settings: FlextAuthSettings,
            dispatcher: p.Dispatcher,
        ) -> None:
            """Initialize all standard managers used by services."""
            self.settings = settings
            self.dispatcher = dispatcher
            self.user_manager = FlextAuthUtilitiesManagers.FlextAuthUserManager(
                settings,
            )
            self.session_manager = FlextAuthUtilitiesManagers.FlextAuthSessionManager(
                settings,
            )
            self.rate_limiter = FlextAuthUtilitiesManagers.FlextAuthRateLimiter(
                settings,
                dispatcher,
            )

    def execute(self) -> p.Result[bool]:
        """Execute method for s interface.

        FlextAuthUtilitiesManagers is a namespace class - use specific manager classes instead.
        """
        return r[bool].fail(
            "FlextAuthUtilitiesManagers is a namespace class - use specific manager classes like FlextAuthUserManager",
        )


__all__: t.MutableSequenceOf[str] = ["FlextAuthUtilitiesManagers"]

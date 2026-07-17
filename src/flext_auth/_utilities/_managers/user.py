"""Auth user manager namespace."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, ClassVar

from flext_api import u

from flext_auth import FlextAuthSettings, m, p, t
from flext_auth._utilities._managers.user_create import FlextAuthUserManagerCreate
from flext_core import FlextContext

if TYPE_CHECKING:
    from collections.abc import MutableMapping


class FlextAuthUserManagers:
    """Namespace for auth user managers."""

    _context_type: ClassVar[p.ContextType] = FlextContext

    class FlextAuthUserManager(FlextAuthUserManagerCreate):
        """User management business logic."""

        config: FlextAuthSettings
        logger: p.Logger
        context: p.Context
        _users: MutableMapping[str, t.Auth.ManagersUserData]
        _DATETIME_ADAPTER: ClassVar[u.TypeAdapter[datetime]] = u.TypeAdapter(datetime)
        _MIN_DATETIME: ClassVar[datetime] = datetime.min.replace(tzinfo=UTC)
        IdentityExtras: ClassVar[type[p.Auth.UserIdentityExtras]] = (
            m.Auth.UserIdentityExtras
        )

        def __init__(self) -> None:
            """Initialize user manager with configuration."""
            super().__init__()
            self.logger = u.fetch_logger(__name__)
            self.context = FlextAuthUserManagers._context_type.create()
            self._users = {}


__all__: list[str] = ["FlextAuthUserManagers"]

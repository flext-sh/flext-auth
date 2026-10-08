"""Auth user manager namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from datetime import UTC, datetime
from typing import ClassVar

from flext_api import u

from flext_auth import FlextAuthSettings, m, p, t
from flext_auth._utilities._managers.user_create import FlextAuthUserManagerCreate


class FlextAuthUserManagers:
    """Namespace for auth user managers."""

    class FlextAuthUserManager(FlextAuthUserManagerCreate):
        """User management business logic."""

        config: FlextAuthSettings
        logger: p.Logger
        _users: MutableMapping[str, t.Auth.ManagersUserData]
        _DATETIME_ADAPTER: ClassVar[m.TypeAdapter[datetime]] = u.type_adapter(datetime)
        _MIN_DATETIME: ClassVar[datetime] = datetime.min.replace(tzinfo=UTC)
        IdentityExtras: ClassVar[type[m.Auth.UserIdentityExtras]] = (
            m.Auth.UserIdentityExtras
        )

        def __init__(self) -> None:
            """Initialize user manager with configuration."""
            super().__init__()
            self.logger = u.fetch_logger(__name__)
            self._users = {}


__all__: list[str] = ["FlextAuthUserManagers"]

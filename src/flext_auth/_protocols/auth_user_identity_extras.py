# AUTO-GENERATED FILE — Regenerate with: make gen
"""Source-derived structural model contracts.

Copyright (c) 2026 FLEXT Team. All rights reserved.
src/flext_auth/_protocols/auth_user_identity_extras
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime
from typing import Protocol, runtime_checkable

from flext_api import FlextApiProtocols


class FlextAuthProtocolsAuthUserIdentityExtras:
    """Own the structural contracts declared by its model source."""

    @runtime_checkable
    class UserIdentityExtras(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        full_name: str | None
        is_active: bool | None
        roles: Sequence[str] | None
        permissions: Sequence[str] | None
        failed_attempts: int | None
        locked_until: datetime | None
        last_access: datetime | None
        token: str | None
        session_id: str | None


__all__: list[str] = [
    "FlextAuthProtocolsAuthUserIdentityExtras",
]

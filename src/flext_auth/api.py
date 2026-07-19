"""FLEXT Auth API facade.

Public entrypoint kept as a strict facade over service classes.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth.services.auth_service import FlextAuthApplicationService

if TYPE_CHECKING:
    from flext_auth import t


class FlextAuth(FlextAuthApplicationService):
    """Authentication facade composing identity, token, session, and provider services."""


auth: FlextAuth = FlextAuth.fetch_global()
"""Process-wide FlextAuth facade singleton resolved from the global container."""


__all__: t.MutableSequenceOf[str] = ["FlextAuth", "auth"]

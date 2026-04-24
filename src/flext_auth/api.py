"""FLEXT Auth API facade.

Public entrypoint kept as a strict facade over service classes.
"""

from __future__ import annotations

from flext_auth import t
from flext_auth.services.auth_service import FlextAuthApplicationService


class FlextAuth(FlextAuthApplicationService):
    """Authentication facade composing identity, token, session, and provider services."""

    pass


auth = FlextAuth.get_global()


__all__: t.MutableSequenceOf[str] = ["FlextAuth", "auth"]

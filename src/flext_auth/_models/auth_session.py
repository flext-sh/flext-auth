"""Authentication token models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from flext_api import m, u

from flext_auth import c


class FlextAuthModelsAuthSession:
    """Session and token entity model namespace."""

    class AuthSession(m.Entity):
        """Generic authentication token entity."""

        identity_id: Annotated[str, m.Field(..., description="Identity ID")]
        token: Annotated[str, m.Field(..., description="Token value", exclude=True)]
        expires_at: Annotated[datetime, m.Field(..., description="Expiration time")]
        token_type: Annotated[str, m.Field(description="Token type")] = (
            c.Auth.TokenTypes.BEARER.value
        )
        session_id: Annotated[str, m.Field(description="Session ID")] = ""
        is_revoked: Annotated[bool, m.Field(description="Revoked status")] = False
        refresh_token: Annotated[
            str,
            m.Field(description="Refresh token", exclude=True),
        ] = ""

        @m.computed_field
        @property
        def user_id(self) -> str:
            """User ID property for protocol compatibility."""
            return self.identity_id

        @m.computed_field
        @property
        def expired(self) -> bool:
            """Whether token is expired."""
            return u.now() > self.expires_at


__all__: list[str] = ["FlextAuthModelsAuthSession"]

"""Authentication token models."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from flext_api import m, u
from flext_auth import c

if TYPE_CHECKING:
    from datetime import datetime


class FlextAuthModelsAuthToken:
    class AuthToken(m.Entity):
        """Generic authentication token entity."""

        identity_id: Annotated[str, u.Field(..., description="Identity ID")]
        token: Annotated[str, u.Field(..., description="Token value", exclude=True)]
        expires_at: Annotated[datetime, u.Field(..., description="Expiration time")]
        token_type: Annotated[
            str,
            u.Field(
                description="Token type",
            ),
        ] = c.Auth.TokenTypes.BEARER.value
        session_id: Annotated[str, u.Field(description="Session ID")] = ""
        is_revoked: Annotated[
            bool,
            u.Field(description="Revoked status"),
        ] = False
        refresh_token: Annotated[
            str,
            u.Field(
                description="Refresh token",
                exclude=True,
            ),
        ] = ""

        @property
        def user_id(self) -> str:
            """User ID property for protocol compatibility."""
            return self.identity_id

        @property
        def expired(self) -> bool:
            """Whether token is expired."""
            current_time: datetime = u.now()
            return current_time > self.expires_at


__all__: list[str] = ["FlextAuthModelsAuthToken"]

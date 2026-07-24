"""Authentication session models."""

from __future__ import annotations

from typing import TYPE_CHECKING, Annotated

from flext_api import m, u

if TYPE_CHECKING:
    from datetime import datetime


class FlextAuthModelsAuthSession:
    class Session(m.Entity):
        """Generic session entity."""

        identity_id: Annotated[str, u.Field(..., description="Identity ID")]
        session_token: Annotated[
            str, u.Field(..., description="Session token", exclude=True)
        ]
        expires_at: Annotated[datetime, u.Field(..., description="Expiration time")]
        is_active: Annotated[bool, u.Field(description="Active status")] = True
        ip_address: Annotated[str, u.Field(description="IP address")] = ""
        user_agent: Annotated[str, u.Field(description="User agent")] = ""
        last_accessed: datetime = u.Field(
            default_factory=u.now, description="Last access"
        )

        @property
        def expired(self) -> bool:
            """Whether session is expired."""
            current_time: datetime = u.now()
            return current_time > self.expires_at


__all__: list[str] = ["FlextAuthModelsAuthSession"]

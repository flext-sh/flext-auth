"""Authentication session protocols."""

from __future__ import annotations

from typing import Protocol, override, runtime_checkable

from flext_auth import p, t


class FlextAuthProtocolsAuthSession:
    @runtime_checkable
    class Session(p.Service[bool], Protocol):
        """Protocol for session-like objects in authentication."""

        id: str
        user_id: str
        session_token: str
        expires_at: t.Auth.DateTimeValue
        is_active: bool
        ip_address: str | None
        user_agent: str | None

        def extend_session(self, hours: int = 1) -> p.Result[bool]:
            """Extend session expiration time."""
            ...

        def expired(self) -> bool:
            """Check if session is expired."""
            ...

        @override
        def valid(self) -> bool:
            """Check if session is valid (active and not expired)."""
            ...

        def revoke(self) -> p.Result[bool]:
            """Revoke this session."""
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthSession"]

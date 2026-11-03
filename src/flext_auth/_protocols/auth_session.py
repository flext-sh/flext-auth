"""Authentication token protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import FlextApiProtocols, p

if TYPE_CHECKING:
    from datetime import datetime

    from flext_auth import t


class FlextAuthProtocolsAuthSession:
    """Protocol namespace for tokens and authentication responses."""

    @runtime_checkable
    class SessionManager(Protocol):
        """Session storage operations consumed by auth services."""

        def cleanup_expired_sessions(self) -> p.Result[int]: ...

        def create_session(
            self,
            user_id: str,
            token: str,
            expires_in_minutes: int = ...,
            ip_address: str | None = None,
            user_agent: str | None = None,
        ) -> p.Result[FlextAuthProtocolsAuthSession.Session]: ...

        def get_active_sessions(
            self,
            user_id: str,
        ) -> p.Result[Sequence[FlextAuthProtocolsAuthSession.Session]]: ...

        def end_session(self, user_id: str) -> p.Result[bool]: ...

        def end_session_by_id(self, session_id: str) -> p.Result[bool]: ...

        def get_total_active_sessions(self) -> int: ...

    @runtime_checkable
    class Token(Protocol):
        """Protocol for token-like objects in authentication.

        Structural typing interface for authentication tokens.
        Supports both model and token implementations.
        """

        @property
        def expires_at(self) -> t.Auth.DateTimeValue:
            """Token expiration time."""
            ...

        @property
        def identity_id(self) -> str:
            """Identity ID (alias for user_id in token context)."""
            ...

        @property
        def expired(self) -> bool:
            """Whether token is expired."""
            ...

        @property
        def is_revoked(self) -> bool:
            """Whether token has been revoked."""
            ...

        @property
        def refresh_token(self) -> str:
            """Refresh token value if applicable."""
            ...

        @property
        def token(self) -> str:
            """Token value."""
            ...

        @property
        def token_type(self) -> str:
            """Token type (e.g. bearer, access)."""
            ...

        @property
        def user_id(self) -> str:
            """User identifier."""
            ...

    @runtime_checkable
    class Session(Token, p.HasModelDump, Protocol):
        """Persisted identity over the existing token contract."""

        @property
        def unique_id(self) -> str: ...

        @property
        def session_id(self) -> str: ...

    @runtime_checkable
    class AuthenticationResponse(Protocol):
        """Protocol for authentication response objects.

        Structural typing interface for authentication responses.
        Supports both TypedDict and model implementations.
        """

        user: t.JsonMapping
        "User/identity data."
        session: t.JsonMapping
        "Session data."
        jwt_token: str
        "JWT token string."
        authenticated: bool
        "Authentication status."
        success: bool
        "Operation success status."

    @runtime_checkable
    class AuthSession(FlextApiProtocols.Model, Protocol):
        """Structural data contract projected from the owning model."""

        @property
        def domain_events(self) -> Sequence[p.DomainEvent]:
            """List of uncommitted domain events for event sourcing."""
            ...

        identity_id: str
        token: str
        expires_at: datetime
        token_type: str
        session_id: str
        is_revoked: bool
        refresh_token: str

        @property
        def user_id(self) -> str:
            """User ID property for protocol compatibility."""
            ...

        @property
        def expired(self) -> bool:
            """Whether token is expired."""
            ...


__all__: list[str] = ["FlextAuthProtocolsAuthSession"]

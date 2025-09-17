"""FLEXT Auth Protocols - Authentication domain protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol

from flext_core import FlextResult


class FlextAuthProtocols:
    """Unified authentication protocols following FLEXT patterns."""

    class FlextAuthUserProtocol(Protocol):
        """Protocol for user-like objects in authentication."""

        id: str
        username: str
        email: str
        is_active: bool
        roles: list[str]
        failed_login_attempts: int
        locked_until: datetime | None

        def verify_password(self, password: str) -> FlextResult[bool]:
            """Verify password against stored hash."""
            ...

        def set_password(self, password: str) -> FlextResult[bool]:
            """Set password with secure hashing."""
            ...

        @property
        def can_login(self) -> bool:
            """Check if user can attempt login."""
            ...

        @property
        def is_locked(self) -> bool:
            """Check if account is currently locked."""
            ...

        def record_successful_login(self) -> None:
            """Record successful login and reset failed attempts."""
            ...

        def record_failed_login(self) -> None:
            """Record failed login attempt and apply lockout if needed."""
            ...

    class FlextAuthSessionProtocol(Protocol):
        """Protocol for session-like objects in authentication."""

        id: str
        user_id: str
        session_token: str
        expires_at: datetime
        is_active: bool
        ip_address: str | None
        user_agent: str | None

        def is_expired(self) -> bool:
            """Check if session is expired."""
            ...

        def extend_session(self, hours: int = 24) -> FlextResult[bool]:
            """Extend session expiration time."""
            ...

        @property
        def is_valid(self) -> bool:
            """Check if session is valid (active and not expired)."""
            ...

        def revoke(self) -> FlextResult[bool]:
            """Revoke this session."""
            ...

    class FlextAuthTokenProtocol(Protocol):
        """Protocol for token-like objects in authentication."""

        token: str
        user_id: str
        expires_at: datetime
        is_revoked: bool

        def is_expired(self) -> bool:
            """Check if token is expired."""
            ...

    class FlextAuthServiceProtocol(Protocol):
        """Protocol for authentication service-like objects."""

        def register_user(
            self,
            username: str,
            email: str,
            password: str,
            full_name: str | None = None,
            roles: list[str] | None = None,
        ) -> FlextResult[FlextAuthProtocols.FlextAuthUserProtocol]:
            """Register new user."""
            ...

        def authenticate_user(
            self,
            username: str,
            password: str,
            client_ip: str | None = None,
            user_agent: str | None = None,
        ) -> FlextResult[dict[str, object]]:
            """Authenticate user and create session."""
            ...

        def logout_user(self, session_id: str) -> FlextResult[None]:
            """Logout user by session ID."""
            ...

        def get_user_by_token(
            self, token: str
        ) -> FlextResult[FlextAuthProtocols.FlextAuthUserProtocol | None]:
            """Get user by JWT token."""
            ...


# Export unified protocols following FLEXT patterns
__all__ = [
    "FlextAuthProtocols",
]

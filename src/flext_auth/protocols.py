"""FLEXT Auth Protocols - Authentication domain protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

# ruff: noqa: ARG002, S106
from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult

from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.typings import FlextAuthTypes


class FlextAuthProtocols(FlextProtocols):
    """Unified authentication protocols following FLEXT domain extension pattern.

    This class consolidates authentication-specific protocols while explicitly
    re-exporting foundation protocols for backward compatibility and clean access.

    Architecture:
        - RE-EXPORTS: Foundation protocols from flext-core for unified access
        - EXTENDS: Authentication-specific protocols in Auth namespace
        - MAINTAINS: Zero breaking changes through explicit re-export pattern

    Usage:
        from flext_auth.protocols import FlextAuthProtocols

        # Foundation access (re-exported)
        FlextAuthProtocols.Foundation.ResultProtocol

        # Authentication-specific access
        FlextAuthProtocols.Auth.UserProtocol
    """

    # =========================================================================
    # AUTHENTICATION-SPECIFIC PROTOCOLS
    # =========================================================================
    # Domain-specific protocols for authentication and authorization operations.

    class Auth:
        """Authentication domain-specific protocols.

        Provides protocols for user authentication, session management,
        token operations, and authentication services.
        """

        @runtime_checkable
        class UserProtocol(FlextProtocols.Service, Protocol):
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
                return FlextResult[bool].ok(True)  # Placeholder implementation

            def set_password(self, password: str) -> FlextResult[bool]:
                """Set password with secure hashing."""
                return FlextResult[bool].ok(True)  # Placeholder implementation

            @property
            def can_login(self) -> bool:
                """Check if user can attempt login."""
                return True  # Placeholder implementation

            @property
            def is_locked(self) -> bool:
                """Check if account is currently locked."""
                return False  # Placeholder implementation

            def record_successful_login(self) -> None:
                """Record successful login and reset failed attempts."""
                # Placeholder implementation

            def record_failed_login(self) -> None:
                """Record failed login attempt and apply lockout if needed."""
                # Placeholder implementation

        @runtime_checkable
        class SessionProtocol(FlextProtocols.Service, Protocol):
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
                return False  # Placeholder implementation

            def extend_session(
                self,
                hours: int = FlextAuthConstants.DEFAULT_SESSION_EXTEND_HOURS,
            ) -> FlextResult[bool]:
                """Extend session expiration time."""
                return FlextResult[bool].ok(True)  # Placeholder implementation

            def is_valid(self) -> bool:
                """Check if session is valid (active and not expired)."""
                return True  # Placeholder implementation

            def revoke(self) -> FlextResult[bool]:
                """Revoke this session."""
                return FlextResult[bool].ok(True)  # Placeholder implementation

        @runtime_checkable
        class TokenProtocol(FlextProtocols.Service, Protocol):
            """Protocol for token-like objects in authentication."""

            token: str
            user_id: str
            expires_at: datetime
            is_revoked: bool

            def is_expired(self) -> bool:
                """Check if token is expired."""
                return False  # Placeholder implementation

        @runtime_checkable
        class ServiceProtocol(FlextProtocols.Service, Protocol):
            """Protocol for authentication service-like objects."""

            def register_user(
                self,
                username: str,
                email: str,
                password: str,
                full_name: str | None = None,
                roles: list[str] | None = None,
            ) -> FlextResult[FlextAuthModels.User]:
                """Register new user."""
                return FlextResult[FlextAuthModels.User].ok(
                    FlextAuthModels.User(
                        user_id=f"user_{username}",
                        username=username,
                        email=email,
                        password_hash="placeholder",
                        full_name=full_name,
                        failed_login_attempts=0,
                        locked_until=None,
                    )
                )  # Placeholder implementation

            def authenticate_user(
                self,
                username: str,
                password: str,
                client_ip: str | None = None,
                user_agent: str | None = None,
            ) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
                """Authenticate user and create session."""
                return FlextResult[FlextAuthTypes.AuthenticationResponseDict].ok({
                    "user": {
                        "id": f"user_{username}",
                        "username": username,
                        "email": f"{username}@example.com",
                        "full_name": None,
                        "is_active": True,
                        "roles": ["user"],
                        "created_at": datetime.now(UTC),
                        "updated_at": datetime.now(UTC),
                        "last_login": None,
                    },
                    "session": {
                        "id": f"session_{username}",
                        "user_id": f"user_{username}",
                        "session_token": f"token_{username}",
                        "expires_at": datetime.now(UTC) + timedelta(hours=24),
                        "created_at": datetime.now(UTC),
                        "last_accessed_at": datetime.now(UTC),
                        "is_active": True,
                        "ip_address": client_ip,
                        "user_agent": user_agent,
                    },
                    "jwt_token": f"jwt_token_{username}",
                    "authenticated": True,
                    "success": True,
                })  # Placeholder implementation

            def logout_user(self, session_id: str) -> FlextResult[None]:
                """Logout user by session ID."""
                return FlextResult[None].ok(None)  # Placeholder implementation


__all__ = [
    "FlextAuthProtocols",
]

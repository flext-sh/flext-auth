"""FLEXT Auth Protocols - Authentication domain protocols.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, runtime_checkable

from flext_core import FlextProtocols, FlextResult, FlextTypes

from flext_auth.models import FlextAuthModels
from flext_auth.typings import FlextAuthTypes


class FlextAuthProtocols:
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
    # FOUNDATION PROTOCOL RE-EXPORTS (from flext-core)
    # =========================================================================
    # Explicitly re-export foundation protocols for unified access.
    # This maintains backward compatibility while providing clean namespace access.

    Foundation = FlextProtocols.Foundation
    Domain = FlextProtocols.Domain
    Application = FlextProtocols.Application
    Infrastructure = FlextProtocols.Infrastructure
    Extensions = FlextProtocols.Extensions
    Commands = FlextProtocols.Commands

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
        class UserProtocol(FlextProtocols.Domain.Service, Protocol):
            """Protocol for user-like objects in authentication."""

            id: str
            username: str
            email: str
            is_active: bool
            roles: FlextTypes.StringList
            failed_login_attempts: int
            locked_until: datetime | None

            def verify_password(self, password: str) -> FlextResult[bool]:
                """Verify password against stored hash."""

            def set_password(self, password: str) -> FlextResult[bool]:
                """Set password with secure hashing."""

            @property
            def can_login(self) -> bool:
                """Check if user can attempt login."""

            @property
            def is_locked(self) -> bool:
                """Check if account is currently locked."""

            def record_successful_login(self) -> None:
                """Record successful login and reset failed attempts."""

            def record_failed_login(self) -> None:
                """Record failed login attempt and apply lockout if needed."""

        @runtime_checkable
        class SessionProtocol(FlextProtocols.Domain.Service, Protocol):
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

            def extend_session(self, hours: int = 24) -> FlextResult[bool]:
                """Extend session expiration time."""

            def is_valid(self) -> bool:
                """Check if session is valid (active and not expired)."""

            def revoke(self) -> FlextResult[bool]:
                """Revoke this session."""

        @runtime_checkable
        class TokenProtocol(FlextProtocols.Domain.Service, Protocol):
            """Protocol for token-like objects in authentication."""

            token: str
            user_id: str
            expires_at: datetime
            is_revoked: bool

            def is_expired(self) -> bool:
                """Check if token is expired."""

        @runtime_checkable
        class ServiceProtocol(FlextProtocols.Domain.Service, Protocol):
            """Protocol for authentication service-like objects."""

            def register_user(
                self,
                username: str,
                email: str,
                password: str,
                full_name: str | None = None,
                roles: FlextTypes.StringList | None = None,
            ) -> FlextResult[FlextAuthModels.User]:
                """Register new user."""

            def authenticate_user(
                self,
                username: str,
                password: str,
                client_ip: str | None = None,
                user_agent: str | None = None,
            ) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
                """Authenticate user and create session."""

            def logout_user(self, session_id: str) -> FlextResult[None]:
                """Logout user by session ID."""

    # =========================================================================
    # BACKWARD COMPATIBILITY ALIASES
    # =========================================================================
    # Maintain existing attribute names for zero breaking changes.

    FlextAuthUserProtocol = Auth.UserProtocol
    FlextAuthSessionProtocol = Auth.SessionProtocol
    FlextAuthTokenProtocol = Auth.TokenProtocol
    FlextAuthServiceProtocol = Auth.ServiceProtocol


__all__ = [
    "FlextAuthProtocols",
]

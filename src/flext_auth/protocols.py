"""FLEXT Auth Protocols - Authentication domain protocols.

Protocol interfaces for authentication and authorization operations.
All protocols organized under single FlextAuthProtocols class per
FLEXT standardization. Uses structural typing only - no model imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime
from typing import Protocol, TypeAlias, override, runtime_checkable

from flext_api import FlextApiProtocols
from flext_core import FlextProtocols


class FlextAuthProtocols(FlextApiProtocols):
    """Unified authentication protocols following FLEXT domain extension pattern.

    This class consolidates authentication-specific protocols while explicitly
    re-exporting foundation protocols for backward compatibility and clean access.

    Architecture:
    - RE-EXPORTS: Foundation protocols from flext-core for unified access
    - EXTENDS: Authentication-specific protocols in Auth namespace
    - MAINTAINS: Zero breaking changes through explicit re-export pattern
    - STRUCTURAL TYPING: No model imports - protocols define structural contracts

    Usage:
    from flext_auth import p

    # Foundation access (inherited)
    p.Result

    # Authentication-specific access
    p.Auth.UserProtocol
    """

    class Auth:
        """Authentication domain-specific protocols.

        Provides protocols for user authentication, session management,
        token operations, and authentication services. All protocols use
        structural typing - no model imports required.
        """

        AuthValue: TypeAlias = object

        @runtime_checkable
        class IdentityProtocol(FlextProtocols.Service[bool], Protocol):
            """Protocol for identity/user-like objects in authentication.

            Structural typing interface for identity objects. Models implement
            this protocol through attribute matching (structural typing).
            """

            id: str
            "Unique identity identifier."
            name: str
            "Identity name/username."
            contact: str
            "Contact information (e.g., email)."
            is_active: bool
            "Active status."
            roles: list[str]
            "Identity roles."
            failed_attempts: int
            "Failed login attempts count."
            locked_until: datetime
            "Lock expiration time (datetime.min means not locked)."

            @property
            def email(self) -> str:
                """Alias for contact property (backward compatibility)."""
                ...

            @property
            def username(self) -> str:
                """Alias for name property (backward compatibility)."""
                ...

            def is_locked(self) -> bool:
                """Check if identity is locked."""
                ...

            def set_credential(self, credential: str) -> FlextProtocols.Result[bool]:
                """Set credential with secure hashing."""
                ...

            def verify_credential(self, credential: str) -> FlextProtocols.Result[bool]:
                """Verify credential against stored hash."""
                ...

        @runtime_checkable
        class UserProtocol(IdentityProtocol, Protocol):
            """Protocol for user-like objects in authentication.

            Extends IdentityProtocol with user-specific methods. Maintains
            backward compatibility with existing UserProtocol interface.
            """

            @property
            def can_login(self) -> bool:
                """Check if user can attempt login."""
                ...

            def record_failed_login(self) -> None:
                """Record failed login attempt and apply lockout if needed."""
                ...

            def record_successful_login(self) -> None:
                """Record successful login and reset failed attempts."""
                ...

        @runtime_checkable
        class SessionProtocol(FlextProtocols.Service[bool], Protocol):
            """Protocol for session-like objects in authentication."""

            id: str
            user_id: str
            session_token: str
            expires_at: datetime
            is_active: bool
            ip_address: str | None
            user_agent: str | None

            def extend_session(self, hours: int = 1) -> FlextProtocols.Result[bool]:
                """Extend session expiration time."""
                ...

            def is_expired(self) -> bool:
                """Check if session is expired."""
                ...

            @override
            def is_valid(self) -> bool:
                """Check if session is valid (active and not expired)."""
                ...

            def revoke(self) -> FlextProtocols.Result[bool]:
                """Revoke this session."""
                ...

        @runtime_checkable
        class TokenProtocol(Protocol):
            """Protocol for token-like objects in authentication.

            Structural typing interface for authentication tokens.
            Supports both model and token implementations.
            """

            @property
            def expires_at(self) -> datetime:
                """Token expiration time."""
                ...

            @property
            def identity_id(self) -> str:
                """Identity ID (alias for user_id in token context)."""
                ...

            @property
            def is_expired(self) -> bool:
                """Check if token is expired."""
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
        class AuthenticationResponseProtocol(Protocol):
            """Protocol for authentication response objects.

            Structural typing interface for authentication responses.
            Supports both TypedDict and model implementations.
            """

            user: Mapping[str, object]
            "User/identity data."
            session: Mapping[str, object]
            "Session data."
            jwt_token: str
            "JWT token string."
            authenticated: bool
            "Authentication status."
            success: bool
            "Operation success status."

        @runtime_checkable
        class ServiceProtocol(FlextProtocols.Service[bool], Protocol):
            """Protocol for authentication service-like objects."""

            def authenticate_user(
                self,
                username: str,
                password: str,
                client_ip: str | None = None,
                user_agent: str | None = None,
            ) -> FlextProtocols.Result[FlextAuthProtocols.Auth.IdentityProtocol]:
                """Authenticate user and return identity.

                Returns IdentityProtocol-compatible identity through structural typing.
                """
                ...

            def logout_user(self, session_id: str) -> FlextProtocols.Result[bool]:
                """Logout user by session ID.

                Returns:
                    FlextProtocols.Result[bool]: True if logout successful, False if failed, error on failure

                """
                ...

            def register_user(
                self,
                username: str,
                email: str,
                password: str,
                full_name: str | None = None,
                roles: list[str] | None = None,
            ) -> FlextProtocols.Result[FlextAuthProtocols.Auth.IdentityProtocol]:
                """Register new user.

                Returns IdentityProtocol-compatible identity through structural typing.
                """
                ...


p = FlextAuthProtocols
__all__ = ["FlextAuthProtocols", "p"]

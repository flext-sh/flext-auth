"""FLEXT Auth Protocols - Authentication domain protocols.

Protocol interfaces for authentication and authorization operations.
All protocols organized under single FlextAuthProtocols class per
FLEXT standardization. Uses structural typing only - no model imports.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import datetime
from typing import Protocol, override, runtime_checkable

from flext_api import p

from flext_auth import c, t


class FlextAuthProtocols(p):
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
    p.Auth.User
    """

    class Auth:
        """Authentication domain-specific protocols.

        Provides protocols for user authentication, session management,
        token operations, and authentication services. All protocols use
        structural typing - no model imports required.
        """

        @runtime_checkable
        class Identity(p.Service[bool], Protocol):
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
            roles: t.StrSequence
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

            def locked(self) -> bool:
                """Check if identity is locked."""
                ...

            def update_credential(self, credential: str) -> p.Result[bool]:
                """Set credential with secure hashing."""
                ...

            def verify_credential(
                self,
                credential: str,
            ) -> p.Result[bool]:
                """Verify credential against stored hash."""
                ...

        @runtime_checkable
        class User(Identity, Protocol):
            """Protocol for user-like objects in authentication.

            Extends Identity with user-specific methods. Maintains
            backward compatibility with existing User interface.
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
        class Session(p.Service[bool], Protocol):
            """Protocol for session-like objects in authentication."""

            id: str
            user_id: str
            session_token: str
            expires_at: datetime
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

        @runtime_checkable
        class Token(Protocol):
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
            def expired(self) -> bool:
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
        class Service(p.Service[bool], Protocol):
            """Protocol for authentication service-like objects."""

            def authenticate_user(
                self,
                username: str,
                password: str,
                client_ip: str | None = None,
                user_agent: str | None = None,
            ) -> p.Result[FlextAuthProtocols.Auth.Identity]:
                """Authenticate user and return identity.

                Returns Identity-compatible identity through structural typing.
                """
                ...

            def logout_user(self, session_id: str) -> p.Result[bool]:
                """Logout user by session ID.

                Returns:
                    FlextApiProtocols.Result[bool]: True if logout successful, False if failed, error on failure

                """
                ...

            def register_user(
                self,
                username: str,
                email: str,
                password: str,
                full_name: str | None = None,
                roles: t.StrSequence | None = None,
            ) -> p.Result[FlextAuthProtocols.Auth.Identity]:
                """Register new user.

                Returns Identity-compatible identity through structural typing.
                """
                ...

        @runtime_checkable
        class RequestWithHeaders(Protocol):
            """Protocol for request-like objects with a headers attribute."""

            headers: t.StrMapping

        @runtime_checkable
        class FlextAuthBaseProvider(Protocol):
            """Base protocol for all authentication providers.

            All authentication providers must implement this interface to ensure
            consistent behavior across different authentication technologies (JWT,
            OAuth2, SAML, etc.).
            """

            def __init__(
                self,
                settings: t.ScalarMapping | None = None,
            ) -> None:
                """Initialize provider with optional configuration."""
                ...

            @property
            def settings(self) -> t.ScalarMapping | None:
                """Get provider configuration."""
                ...

            def authenticate(
                self,
                credentials: t.JsonMapping,
            ) -> p.Result[FlextAuthProtocols.Auth.Token]:
                """Authenticate user with provided credentials.

                This is the primary authentication method. It should validate the
                provided credentials and, if valid, return an authentication token.

                Args:
                    credentials: Dictionary containing authentication credentials.
                                The exact structure depends on the provider type.

                Returns:
                    r[p.Auth.Token]: Authentication token on success,
                                        error message on failure

                """
                ...

            def generate_token(
                self,
                payload: t.JsonMapping,
                token_kind: str = c.Auth.TokenTypes.ACCESS.value,
                expiry_minutes: int | None = None,
            ) -> p.Result[str]:
                """Generate a signed token from the provided payload."""
                ...

            def generate_token_for_user(
                self,
                user: t.JsonMapping,
                token_kind: str = c.Auth.TokenTypes.ACCESS.value,
                token_type: str | None = None,
                expiry_minutes: int | None = None,
            ) -> p.Result[str]:
                """Generate token for a user identity or claims mapping.

                Args:
                    user: User claims dict
                    token_kind: Token type (access, refresh, id, bearer)
                    token_type: Explicit token type override if requested
                    expiry_minutes: Token expiration time in minutes (optional)

                Returns:
                    r[str]: Encoded token string on success, error on failure

                """
                ...

            def refresh(
                self,
                token: str,
            ) -> p.Result[FlextAuthProtocols.Auth.Token]:
                """Refresh authentication token.

                Generate a new token based on an existing valid token. This operation
                is optional and should return an error if the provider doesn't support
                token refresh.

                Args:
                    token: Existing token to refresh

                Returns:
                    r[FlextAuthProtocols.Auth.Token]: New token on success,
                                        error if refresh not supported or failed

                """
                ...

            def revoke(self, token: str) -> p.Result[bool]:
                """Revoke authentication token.

                Invalidate the provided token, preventing further use. This operation
                is optional and should return an error if the provider doesn't support
                token revocation.

                Args:
                    token: Token to revoke

                Returns:
                    r[bool]: True if revoked successfully,
                        False if revocation not supported or failed,
                        error message on failure

                """
                ...

            def supports(self) -> set[str]:
                """Return set of capabilities supported by this provider.

                Capabilities help consumers understand what operations are available
                for this provider. This allows graceful degradation when using providers
                with different feature sets.

                Returns:
                    set[str]: Set of supported operations

                """
                ...

            def validate(self, token: str) -> p.Result[bool]:
                """Validate authentication token.

                Check if the provided token is valid and has not expired.

                Args:
                    token: Token to validate

                Returns:
                    r[bool]: True if valid, False if invalid, error on failure

                """
                ...

        @runtime_checkable
        class BaseTransportAdapter(Protocol):
            """Protocol for transport adapters.

            Transport adapters enable authentication operations over different
            communication protocols (HTTP, gRPC, WebSocket, etc.).

            All transport implementations must implement this protocol to ensure
            consistent interface across different transport mechanisms.

            Example:
                >>> class FlextWebTransportAdapter(BaseTransportAdapter):
                ...     def send_request(
                ...         self,
                ...         url: str,
                ...         method: str = "POST",
                ...         data: t.ConfigurationMapping | None = None,
                ...         headers: t.StrMapping | None = None,
                ...     ) -> p.Result[t.ConfigurationMapping]:
                ...         # HTTP-specific implementation
                ...         pass

            """

            def get_transport_type(self) -> str:
                """Get the transport type identifier.

                Returns:
                    str: Transport type (e.g., "http", "grpc", "websocket")

                """
                ...

            def send_request(
                self,
                url: str,
                method: str = "POST",
                data: t.ConfigurationMapping | None = None,
                headers: t.StrMapping | None = None,
                **kwargs: t.Scalar,
            ) -> p.Result[t.ConfigurationMapping]:
                """Send a request using this transport.

                Args:
                url: Target URL or endpoint
                method: HTTP method or operation type
                data: Request payload data
                headers: Request headers or metadata
                **kwargs: Transport-specific additional parameters

                Returns:
                r containing response data or error

                """
                ...


p = FlextAuthProtocols
__all__: list[str] = ["FlextAuthProtocols", "p"]

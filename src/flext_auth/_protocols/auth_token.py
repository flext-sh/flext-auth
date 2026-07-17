"""Authentication token protocols."""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from flext_auth import t


class FlextAuthProtocolsAuthToken:
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


__all__: list[str] = ["FlextAuthProtocolsAuthToken"]

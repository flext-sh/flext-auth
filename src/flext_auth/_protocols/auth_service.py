"""Authentication service protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import p

if TYPE_CHECKING:
    from flext_auth import t
    from flext_auth._protocols import (
        FlextAuthProtocolsAuthIdentity,
        FlextAuthProtocolsAuthProvider,
    )


class FlextAuthProtocolsAuthService:
    """Protocol namespace for auth and provider services."""

    @runtime_checkable
    class Service(p.Service[bool], Protocol):
        """Protocol for authentication service-like objects."""

        def authenticate_user(
            self,
            username: str,
            password: str,
            client_ip: str | None = None,
            user_agent: str | None = None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]:
            """Authenticate user and return identity.

            Returns Identity-compatible identity through structural typing.

            Args:
                username: Account name to authenticate.
                password: Plain credential for the account.
                client_ip: Optional client address for audit.
                user_agent: Optional client agent for audit.

            Returns:
                The authenticated identity; failure when authentication is
                rejected.

            """
            ...

        def logout_user(self, session_id: str) -> p.Result[bool]:
            """Logout user by session ID.

            Args:
                session_id: Identifier of the session to terminate.

            Returns:
                Whether the logout succeeded.

            """
            ...

        def register_user(
            self,
            username: str,
            email: str,
            password: str,
            full_name: str | None = None,
            roles: t.StrSequence | None = None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]:
            """Register new user.

            Returns Identity-compatible identity through structural typing.

            Args:
                username: Unique account name for the new identity.
                email: Contact address bound to the identity.
                password: Plain credential to hash before storage.
                full_name: Optional display name.
                roles: Optional role names to grant.

            Returns:
                The created identity; failure on validation errors.

            """
            ...

    @runtime_checkable
    class ProviderService(Protocol):
        """Protocol for provider services consumed by token workflows."""

        def fetch_jwt_provider(
            self,
        ) -> p.Result[FlextAuthProtocolsAuthProvider.FlextAuthBaseProvider]:
            """Resolve the JWT authentication provider through the registry.

            Returns:
                The registered JWT provider; failure when absent.

            """
            ...

    @runtime_checkable
    class IdentityService(Protocol):
        """Identity use cases required by the public authentication facade."""

        def authenticate_identity(
            self,
            name: str,
            credential: str,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]: ...

        def create_identity(
            self,
            name: str,
            contact: str,
            credential: str,
            roles: t.StrSequence | None = None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]: ...

    @runtime_checkable
    class SessionService(Protocol):
        """Token and session capabilities consumed by the application service."""

        @property
        def session_manager(self) -> FlextAuthProtocolsAuthSession.SessionManager: ...

        def generate_jwt_token(
            self,
            user_id: str,
            expires_in_minutes: int | None = None,
            token_kind: str = ...,
        ) -> p.Result[str]: ...

    @runtime_checkable
    class RequestWithHeaders(Protocol):
        """Protocol for request-like objects with a headers attribute."""

        headers: t.StrMapping


__all__: list[str] = ["FlextAuthProtocolsAuthService"]

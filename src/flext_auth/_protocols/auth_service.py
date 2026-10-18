"""Authentication service protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import p

from flext_auth._protocols import FlextAuthProtocolsAuthProvider

if TYPE_CHECKING:
    from flext_auth import t
    from flext_auth._protocols import (
        FlextAuthProtocolsAuthIdentity,
        FlextAuthProtocolsAuthSession,
    )


class FlextAuthProtocolsAuthService:
    """Protocol namespace for auth and provider services."""

    @runtime_checkable
    class ApplicationConfig(Protocol):
        """Settings capability used by application session orchestration."""

        @property
        def session_expiry_minutes(self) -> int: ...

        @property
        def expiry_minutes(self) -> int: ...

    @runtime_checkable
    class Service(
        p.Service[bool], FlextAuthProtocolsAuthProvider.ProviderRegistry, Protocol
    ):
        """Protocol for authentication service-like objects."""

        @property
        def registry(self) -> p.Registry: ...

        @property
        def identity_service(self) -> FlextAuthProtocolsAuthService.IdentityService: ...

        @property
        def session_service(self) -> FlextAuthProtocolsAuthService.SessionService: ...

        def authenticate(
            self, credentials: t.StrMapping
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]: ...

        def create_token(self, identity_id: str) -> p.Result[str]: ...

        def authenticate_user(
            self,
            username: str,
            password: str,
            ip_address: str | None = None,
            user_agent: str | None = None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]:
            """Authenticate user and return identity.

            Returns Identity-compatible identity through structural typing.

            Args:
                username: Account name to authenticate.
                password: Plain credential for the account.
                ip_address: Optional client address for audit.
                user_agent: Optional client agent for audit.

            Returns:
                The authenticated identity; failure when authentication is
                rejected.

            """
            ...

        def register_user(
            self,
            username: str,
            email: str,
            password: str,
            roles: t.StrSequence | None = None,
            role: str | None = None,
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]:
            """Register new user.

            Returns Identity-compatible identity through structural typing.

            Args:
                username: Unique account name for the new identity.
                email: Contact address bound to the identity.
                password: Plain credential to hash before storage.
                roles: Optional role names to grant.
                role: Optional single role name to grant.

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

        @property
        def identity_manager(
            self,
        ) -> FlextAuthProtocolsAuthIdentity.IdentityManager: ...

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

        def authorize_identity(
            self,
            identity_id: str,
            permission: str,
            resource: str | None = None,
        ) -> p.Result[bool]: ...

        def change_credential(
            self,
            identity_id: str,
            current_credential: str,
            new_credential: str,
        ) -> p.Result[bool]: ...

        def reset_credential(
            self,
            identity_id: str,
            new_credential: str,
        ) -> p.Result[bool]: ...

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

        def validate_token(self, token: str) -> p.Result[bool]: ...

        def refresh_token(
            self, token: str
        ) -> p.Result[FlextAuthProtocolsAuthSession.Session]: ...

        def cleanup_expired_sessions(self) -> p.Result[int]: ...

    @runtime_checkable
    class RequestWithHeaders(Protocol):
        """Protocol for request-like objects with a headers attribute."""

        headers: t.StrMapping


__all__: list[str] = ["FlextAuthProtocolsAuthService"]

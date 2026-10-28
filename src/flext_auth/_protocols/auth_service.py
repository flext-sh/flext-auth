"""Authentication service protocols.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import p

from flext_auth._protocols import FlextAuthProtocolsAuthProvider

if TYPE_CHECKING:
    from flext_auth._protocols import (
        FlextAuthProtocolsAuthIdentity,
        FlextAuthProtocolsAuthSession,
    )


class FlextAuthProtocolsAuthService:
    """Protocol namespace for auth and provider services."""

    @runtime_checkable
    class ApplicationConfig(p.HasModelDump, Protocol):
        """Settings capability used by application session orchestration."""

        @property
        def session_expiry_minutes(self) -> int: ...

        @property
        def expiry_minutes(self) -> int: ...

    @runtime_checkable
    class Settings(p.Settings, Protocol):
        """Auth namespace capability over the existing core settings contract."""

        Auth: FlextAuthProtocolsAuthService.ApplicationConfig

    @runtime_checkable
    class ProviderService(Protocol):
        """Minimal provider resolution capability consumed by token workflows."""

        def fetch_jwt_provider(
            self,
        ) -> p.Result[FlextAuthProtocolsAuthProvider.FlextAuthBaseProvider]: ...

    @runtime_checkable
    class Service(
        p.Service[bool],
        FlextAuthProtocolsAuthProvider.ProviderRegistry,
        ProviderService,
        Protocol,
    ):
        """Protocol for authentication service-like objects."""

        @property
        def registry(self) -> p.Registry: ...

        @property
        def settings(self) -> FlextAuthProtocolsAuthService.Settings: ...

        @property
        def config(self) -> FlextAuthProtocolsAuthService.ApplicationConfig: ...

        @property
        def identity_service(self) -> FlextAuthProtocolsAuthService.IdentityService: ...

        @property
        def session_service(self) -> FlextAuthProtocolsAuthService.SessionService: ...

        def authenticate(
            self, credentials: Mapping[str, str]
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]: ...

        def create_token(self, identity_id: str) -> p.Result[str]: ...

        def authenticate_with_provider(
            self,
            username: str,
            password: str,
            provider: str = ...,
        ) -> p.Result[FlextAuthProtocolsAuthSession.Token]: ...

        def generate_token_for_user(
            self,
            user: FlextAuthProtocolsAuthIdentity.Identity,
            provider: str = ...,
            token_kind: str = ...,
            token_type: str | None = None,
            expiry_minutes: int | None = None,
        ) -> p.Result[str]: ...

        def validate_token(self, token: str, provider: str = ...) -> p.Result[bool]: ...

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
            roles: Sequence[str] | None = None,
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
            roles: Sequence[str] | None = None,
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
        def user_manager(self) -> FlextAuthProtocolsAuthIdentity.IdentityManager: ...

        @property
        def provider_service(self) -> FlextAuthProtocolsAuthService.ProviderService: ...

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

        headers: Mapping[str, str]


__all__: list[str] = ["FlextAuthProtocolsAuthService"]

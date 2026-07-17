"""Authentication service protocols."""

from __future__ import annotations

from typing import TYPE_CHECKING, Protocol, runtime_checkable

from flext_api import p

from flext_auth import p, t

if TYPE_CHECKING:
    from flext_auth._protocols.auth_identity import FlextAuthProtocolsAuthIdentity


class FlextAuthProtocolsAuthService:
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
        ) -> p.Result[FlextAuthProtocolsAuthIdentity.Identity]:
            """Register new user.

            Returns Identity-compatible identity through structural typing.
            """
            ...

    @runtime_checkable
    class RequestWithHeaders(Protocol):
        """Protocol for request-like objects with a headers attribute."""

        headers: t.StrMapping


__all__: list[str] = ["FlextAuthProtocolsAuthService"]

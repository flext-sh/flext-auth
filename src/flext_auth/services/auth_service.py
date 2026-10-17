"""FLEXT Auth application service.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import override

from flext_auth import FlextAuthRegistry, FlextAuthSettings, c, m, p, r, t, u
from flext_auth.services import (
    FlextAuthApplicationLifecycle,
    FlextAuthIdentityService,
    FlextAuthProviderService,
    FlextAuthSessionService,
)


class FlextAuthApplicationService(FlextAuthApplicationLifecycle):
    """Authentication application service used by the API composition."""

    _registry: FlextAuthRegistry = m.PrivateAttr()
    _provider_service: FlextAuthProviderService = m.PrivateAttr()
    _identity_service: FlextAuthIdentityService = m.PrivateAttr()
    _session_service: FlextAuthSessionService = m.PrivateAttr()

    def __init__(self, *, runtime_settings: p.Settings | None = None) -> None:
        """Initialize with dependency injection and event bus.

        Args:
            runtime_settings: Optional settings instance overriding the global auth
                settings.

        """
        super().__init__(runtime_settings=runtime_settings)
        self._registry = FlextAuthRegistry()
        dispatcher = self.container.dispatcher().unwrap()
        shared_managers = u.Auth.ServiceManagers(dispatcher)
        self._provider_service = FlextAuthProviderService(
            runtime_settings=self.settings,
            registry=self._registry,
        )
        self._identity_service = FlextAuthIdentityService(
            dispatcher=dispatcher,
            managers=shared_managers,
        )
        self._session_service = FlextAuthSessionService(
            provider_service=self._provider_service,
            dispatcher=dispatcher,
            managers=shared_managers,
        )

    @property
    def config(self) -> FlextAuthSettings.AuthSettings:
        """The namespaced auth configuration (``settings.Auth``)."""
        return self.settings.Auth

    @property
    def identity_service(self) -> FlextAuthIdentityService:
        """The identity service handling credential resolution."""
        return self._identity_service

    @property
    def registry(self) -> FlextAuthRegistry:
        """The provider registry holding registered auth providers."""
        return self._registry

    @property
    def session_service(self) -> FlextAuthSessionService:
        """The session service managing authentication sessions."""
        return self._session_service

    def authenticate(self, credentials: t.StrMapping) -> p.Result[m.Auth.AuthIdentity]:
        """Validate credentials mapping and dispatch to the identity service.

        Args:
            credentials: Mapping holding ``username`` and ``password`` keys.

        Returns:
            The authenticated identity; failure when keys are missing or
            authentication is rejected.

        """
        username = credentials.get("username") or ""
        password = credentials.get("password") or ""
        if not username or not password:
            return r[m.Auth.AuthIdentity].fail(
                "Invalid credentials: username and password required",
            )
        return self._identity_service.authenticate_identity(username, password)

    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Authenticate and provision token + session for the user.

        Args:
            username: Account name to authenticate.
            password: Plain credential for the account.
            ip_address: Optional client address recorded on the session.
            user_agent: Optional client agent recorded on the session.

        Returns:
            The identity carrying its fresh token and session ID; failure
            when authentication, token creation, or session creation fails.

        """
        auth_result = self._identity_service.authenticate_identity(username, password)
        if auth_result.failure:
            return auth_result
        identity = auth_result.value
        token_result = self._session_service.generate_jwt_token(
            user_id=identity.unique_id,
        )
        if token_result.failure:
            return r[m.Auth.AuthIdentity].from_failure(token_result)
        session_result = self._session_service.session_manager.create_session(
            user_id=identity.unique_id,
            token=token_result.value,
            expires_in_minutes=self.config.session_expiry_minutes,
            ip_address=ip_address or "",
            user_agent=user_agent or "",
        )
        if session_result.failure:
            return r[m.Auth.AuthIdentity].from_failure(session_result)
        identity.token = token_result.value
        identity.session_id = session_result.value.unique_id
        return r[m.Auth.AuthIdentity].ok(identity)

    @override
    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: t.StrSequence | None = None,
        role: str | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Register user with default USER role if none provided.

        Args:
            username: Unique account name for the new identity.
            email: Contact address bound to the identity.
            password: Plain credential to hash before storage.
            roles: Optional role names to grant.
            role: Optional single legacy role name to grant.

        Returns:
            The created identity entity.

        """
        if roles is not None:
            user_roles = roles
        elif role is not None:
            user_roles = [role]
        else:
            user_roles = [c.Auth.RoleTypes.USER.value]
        return self._identity_service.create_identity(
            name=username,
            contact=email,
            credential=password,
            roles=user_roles,
        )

    def create_token(self, identity_id: str) -> p.Result[str]:
        """Create a token applying the configured default expiry.

        Args:
            identity_id: Identifier of the identity to mint a token for.

        Returns:
            The signed token string; failure when the identifier is empty.

        """
        match identity_id:
            case str() as identity if identity:
                identity_id = identity
            case _:
                return r[str].fail("Identity ID must be a non-empty string")
        return self._session_service.generate_jwt_token(user_id=identity_id)


__all__: t.MutableSequenceOf[str] = ["FlextAuthApplicationService"]

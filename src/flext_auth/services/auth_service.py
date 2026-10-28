"""FLEXT Auth application service.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence

from flext_auth import c, m, p, r
from flext_auth.services import FlextAuthProviderService


class FlextAuthApplicationService(
    FlextAuthProviderService, m.Auth.ApplicationPortOptions
):
    """Authentication application service used by the API composition."""

    @property
    def config(self) -> p.Auth.ApplicationConfig:
        """The namespaced auth configuration (``settings.Auth``)."""
        return self.settings.Auth

    def authenticate(self, credentials: Mapping[str, str]) -> p.Result[p.Auth.Identity]:
        """Validate credentials mapping and dispatch to the identity service.

        Args:
            credentials: Mapping holding ``username`` and ``password`` keys.

        Returns:
            The authenticated identity; failure when keys are missing or
            authentication is rejected.

        """
        username = credentials.get("username")
        password = credentials.get("password")
        if not username or not password:
            return r[p.Auth.Identity].fail(
                "Invalid credentials: username and password required",
            )
        return self.identity_service.authenticate_identity(username, password)

    def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> p.Result[p.Auth.Identity]:
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
        auth_result = self.identity_service.authenticate_identity(username, password)
        if auth_result.failure:
            return auth_result
        identity = auth_result.value
        token_result = self.session_service.generate_jwt_token(
            user_id=identity.unique_id,
        )
        if token_result.failure:
            return r[p.Auth.Identity].from_failure(token_result)
        session_result = self.session_service.session_manager.create_session(
            user_id=identity.unique_id,
            token=token_result.value,
            expires_in_minutes=self.config.session_expiry_minutes,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        if session_result.failure:
            return r[p.Auth.Identity].from_failure(session_result)
        identity.token = token_result.value
        identity.session_id = session_result.value.unique_id
        return auth_result

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: Sequence[str] | None = None,
        role: str | None = None,
    ) -> p.Result[p.Auth.Identity]:
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
        return self.identity_service.create_identity(
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
        return self.session_service.generate_jwt_token(user_id=identity_id)


__all__: MutableSequence[str] = ["FlextAuthApplicationService"]

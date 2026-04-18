"""Identity concern mixin for the FlextAuth service facade."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth import c, m, p, r, t

if TYPE_CHECKING:
    from flext_auth.services.identity_service import FlextAuthIdentityService
    from flext_auth.services.session_service import FlextAuthSessionService
    from flext_auth.services.token_service import FlextAuthTokenService
    from flext_auth.settings import FlextAuthSettings


class FlextAuthIdentityMixin:
    """Identity lifecycle concern: authentication, registration, and CRUD."""

    _identity_service: FlextAuthIdentityService
    _token_service: FlextAuthTokenService
    _session_service: FlextAuthSessionService
    _config: FlextAuthSettings
    logger: p.Logger

    def create_token(
        self,
        identity_id: str,
        extra_claims: t.ConfigurationMapping | None = None,
    ) -> p.Result[str]:
        """Token creation hook implemented by the composing class."""
        ...

    def authenticate(
        self,
        credentials: t.StrMapping,
        _provider: str | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Railway-oriented authentication."""
        username_value = credentials.get("username")
        match username_value:
            case str() as username if username:
                username_value = username
            case _:
                return r[m.Auth.AuthIdentity].fail(
                    "Invalid credentials: username required",
                )
        password_value = credentials.get("password")
        match password_value:
            case str() as password if password:
                password_value = password
            case _:
                return r[m.Auth.AuthIdentity].fail(
                    "Invalid credentials: password required",
                )
        return self._identity_service.authenticate_identity(
            username_value,
            password_value,
        )

    def authenticate_user(
        self,
        username: str,
        password: str,
        _ip_address: str | None = None,
        _user_agent: str | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Authenticate user with token and session creation."""
        auth_result = self._identity_service.authenticate_identity(username, password)
        if auth_result.success:
            identity = auth_result.value
            token_result = self.create_token(identity_id=identity.unique_id)
            if token_result.success:
                token = token_result.value
                session_result = self._session_service.session_manager.create_session(
                    user_id=identity.unique_id,
                    token=token,
                    expires_in_minutes=self._config.session_expiry_minutes,
                    ip_address=_ip_address or "",
                    user_agent=_user_agent or "",
                )

                def _log_session_error(err: str) -> None:
                    self.logger.warning(
                        f"Failed to create session for user {identity.name}: {err}",
                    )

                session_result.tap_error(_log_session_error)
        return auth_result

    def delete_user(self, user_id: str) -> p.Result[bool]:
        """Delete user identity."""
        return self._identity_service.identity_manager.delete_user(user_id)

    def get_user(self, user_id: str) -> p.Result[m.Auth.AuthIdentity]:
        """Get user by ID."""
        return self._identity_service.identity_manager.get_user(user_id)

    def get_user_by_username(self, username: str) -> p.Result[m.Auth.AuthIdentity]:
        """Get user by username."""
        return self._identity_service.identity_manager.get_user_by_username(username)

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: t.StrSequence | None = None,
        role: str | None = None,
        **kwargs: t.Scalar | t.StrSequence | None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Register new user with roles."""
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
            **kwargs,
        )

    def register_user_simple(
        self,
        username: str,
        email: str,
        password: str,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Register new user (simple form)."""
        return self._identity_service.create_identity(
            name=username,
            contact=email,
            credential=password,
        )

    def update_user(
        self,
        user_id: str,
        **updates: t.Scalar | t.StrSequence | None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Update user identity."""
        return self._identity_service.identity_manager.update_user(user_id, **updates)

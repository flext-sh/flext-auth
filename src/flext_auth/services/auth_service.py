"""FLEXT Auth application service."""

from __future__ import annotations

from typing import ClassVar, override

from flext_auth import (
    FlextAuthIdentityService,
    FlextAuthProviderService,
    FlextAuthRegistry,
    FlextAuthSessionService,
    FlextAuthSettings,
    FlextAuthTokenService,
    c,
    m,
    p,
    r,
    settings,
    t,
)
from flext_auth._utilities.managers import FlextAuthUtilitiesManagers
from flext_auth.services._auth_lifecycle import FlextAuthApplicationLifecycle
from flext_core import FlextContainer


class FlextAuthApplicationService(FlextAuthApplicationLifecycle):
    """Authentication application service used by the API composition."""

    _container_type: ClassVar[p.ContainerType] = FlextContainer
    _registry: FlextAuthRegistry
    _dispatcher: p.Dispatcher
    _provider_service: FlextAuthProviderService
    _identity_service: FlextAuthIdentityService
    _token_service: FlextAuthTokenService
    _session_service: FlextAuthSessionService
    _auth_settings: FlextAuthSettings

    def __init__(
        self,
        settings: FlextAuthSettings | None = None,
    ) -> None:
        """Initialize with dependency injection and event bus."""
        resolved_settings = (
            settings if settings is not None else FlextAuthSettings.fetch_global()
        )
        self._auth_settings = resolved_settings
        self._registry = FlextAuthRegistry()
        self._dispatcher = self._container_type.shared().dispatcher().unwrap()
        shared_managers = FlextAuthUtilitiesManagers.ServiceManagers(
            self._dispatcher,
        )
        self._provider_service = FlextAuthProviderService(
            settings=resolved_settings,
            registry=self._registry,
        )
        self._identity_service = FlextAuthIdentityService(
            dispatcher=self._dispatcher,
            managers=shared_managers,
        )
        self._token_service = FlextAuthTokenService(
            provider_service=self._provider_service,
            dispatcher=self._dispatcher,
            managers=shared_managers,
        )
        self._session_service = FlextAuthSessionService(
            dispatcher=self._dispatcher,
            managers=shared_managers,
        )

    @property
    def settings(self) -> FlextAuthSettings:
        """The resolved auth settings bound to this facade."""
        return self._auth_settings

    @property
    def config(self) -> FlextAuthSettings.AuthSettings:
        """The namespaced auth configuration (``settings.Auth``)."""
        return self._auth_settings.Auth

    @property
    def identity_service(self) -> FlextAuthIdentityService:
        """Identity service access."""
        return self._identity_service

    @property
    def registry(self) -> FlextAuthRegistry:
        """Registry access."""
        return self._registry

    @property
    def session_service(self) -> FlextAuthSessionService:
        """Session service access."""
        return self._session_service

    @property
    def token_service(self) -> FlextAuthTokenService:
        """Token service access."""
        return self._token_service

    def authenticate(
        self,
        credentials: t.StrMapping,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Validate credentials mapping and dispatch to the identity service."""
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
        """Authenticate and provision token + session for the user."""
        auth_result = self._identity_service.authenticate_identity(username, password)
        if auth_result.success:
            identity = auth_result.value
            token_result = self._token_service.generate_jwt_token(
                user_id=identity.unique_id,
                expires_in_minutes=settings.Auth.expiry_minutes,
            )
            if token_result.success:
                session_result = self._session_service.session_manager.create_session(
                    user_id=identity.unique_id,
                    token=token_result.value,
                    expires_in_minutes=settings.Auth.session_expiry_minutes,
                    ip_address=ip_address or "",
                    user_agent=user_agent or "",
                )

                session_result.tap_error(
                    lambda err: (
                        self.logger.warning(
                            "Failed to create session for user %s: %s",
                            identity.name,
                            err,
                        ),
                        None,
                    )[-1],
                )
        return auth_result

    @override
    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: t.StrSequence | None = None,
        role: str | None = None,
    ) -> p.Result[m.Auth.AuthIdentity]:
        """Register user with default USER role if none provided."""
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
        """Create a token applying the settingsured default expiry."""
        match identity_id:
            case str() as identity if identity:
                identity_id = identity
            case _:
                return r[str].fail("Identity ID must be a non-empty string")
        return self._token_service.generate_jwt_token(
            user_id=identity_id,
            expires_in_minutes=settings.Auth.expiry_minutes,
        )


__all__: t.MutableSequenceOf[str] = ["FlextAuthApplicationService"]

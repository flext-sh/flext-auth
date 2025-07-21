"""Dependency injection for FastAPI app."""

from __future__ import annotations

from functools import lru_cache

from flext_auth.application.command_auth_service import AuthService
from flext_auth.infrastructure.container import AuthContainer


@lru_cache
def get_container() -> AuthContainer:
    """Get dependency injection container."""
    return AuthContainer()


def get_auth_service() -> AuthService:
    """Get authentication service dependency."""
    container = get_container()
    auth_service = container.auth_service
    # Type assertion for mypy - container should return correct type
    if not isinstance(auth_service, AuthService):
        msg = f"Expected AuthService, got {type(auth_service)}"
        raise TypeError(msg)
    return auth_service

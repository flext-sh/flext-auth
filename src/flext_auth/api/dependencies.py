"""Dependency injection for FastAPI app."""

from __future__ import annotations

from functools import lru_cache

from flext_auth.infrastructure.container import AuthContainer
from flext_auth.infrastructure.implementations.authentication_implementation import (
    EnterpriseAuthService,
)


@lru_cache
def get_container() -> AuthContainer:
    """Get dependency injection container."""
    return AuthContainer()


def get_auth_service() -> EnterpriseAuthService:
    """Get authentication service dependency."""
    container = get_container()
    auth_service = container.auth_service
    # Type assertion for mypy - container should return correct type
    if not isinstance(auth_service, EnterpriseAuthService):
        msg = f"Expected EnterpriseAuthService, got {type(auth_service)}"
        raise TypeError(msg)
    return auth_service

"""Dependency injection for FastAPI app."""

from __future__ import annotations

from functools import lru_cache
from typing import TYPE_CHECKING

from flext_auth.infrastructure.container import Container

if TYPE_CHECKING:
    from flext_auth.application.command_auth_service import AuthService


@lru_cache
def get_container() -> Container:
    """Get dependency injection container."""
    return Container()


def get_auth_service() -> AuthService:
    """Get authentication service dependency."""
    container = get_container()
    return container.auth_service()

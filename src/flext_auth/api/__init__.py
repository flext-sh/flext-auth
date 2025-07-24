"""FastAPI authentication API module."""

from __future__ import annotations

from flext_auth.api.endpoints import app, create_auth_router

__all__ = ["app", "create_auth_router"]

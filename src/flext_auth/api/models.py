"""API models for FLEXT Auth endpoints."""
from __future__ import annotations

from typing import TYPE_CHECKING, Any

from pydantic import BaseModel, EmailStr, Field

if TYPE_CHECKING:
    from datetime import datetime


class CreateUserRequest(BaseModel):
    """Request model for user creation."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    roles: list[str] | None = None


class AuthenticateRequest(BaseModel):
    """Request model for user authentication."""

    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class ChangePasswordRequest(BaseModel):
    """Request model for password change."""

    current_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8)


class UserResponse(BaseModel):
    """Response model for user data."""

    id: str
    username: str
    email: str
    is_active: bool
    created_at: datetime


class AuthenticateResponse(BaseModel):
    """Response model for authentication."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int


class ErrorResponse(BaseModel):
    """Response model for errors."""

    message: str
    error_type: str | None = None
    details: dict[str, Any] | None = None


# Rebuild models to resolve forward references
def rebuild_api_models() -> None:
    """Rebuild all API models with proper type resolution."""
    import sys
    from datetime import datetime
    current_module = sys.modules[__name__]
    # Add types to module globals for Pydantic model resolution
    # Use setattr to properly expose types for Pydantic model resolution
    current_module.datetime = datetime
    # Rebuild models that use forward references
    UserResponse.model_rebuild()


# Only rebuild if not in TYPE_CHECKING
_models_rebuilt = False


def ensure_api_models_rebuilt() -> None:
    """Ensure API models are rebuilt with proper type resolution."""
    import typing
    global _models_rebuilt
    if _models_rebuilt:
        return
    # Only rebuild in runtime, not during static analysis
    if not typing.TYPE_CHECKING:
        try:
            rebuild_api_models()
            _models_rebuilt = True
        except ImportError:
            # If there are still import issues, models will work with limited type safety
            pass

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

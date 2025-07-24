"""Pydantic models for API request/response validation."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, EmailStr, Field


class RegisterRequest(BaseModel):
    """User registration request model."""

    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="Email address")
    password: str = Field(..., min_length=8, max_length=128, description="Password")


class LoginRequest(BaseModel):
    """User login request model."""

    username: str = Field(..., description="Username")
    password: str = Field(..., description="Password")


class ChangePasswordRequest(BaseModel):
    """Password change request model."""

    current_password: str = Field(..., description="Current password")
    new_password: str = Field(
        ..., min_length=8, max_length=128, description="New password"
    )


class RefreshTokenRequest(BaseModel):
    """Token refresh request model."""

    refresh_token: str = Field(..., description="Refresh token")


class UserResponse(BaseModel):
    """User response model."""

    id: str = Field(..., description="User ID")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    role: str = Field(..., description="User role")
    status: str = Field(..., description="Account status")
    last_login: str | None = Field(None, description="Last login timestamp")
    created_at: str = Field(..., description="Account creation timestamp")


class SessionResponse(BaseModel):
    """Session response model."""

    id: str = Field(..., description="Session ID")
    status: str = Field(..., description="Session status")
    ip_address: str | None = Field(None, description="IP address")
    user_agent: str | None = Field(None, description="User agent")
    created_at: str = Field(..., description="Session creation timestamp")
    last_accessed: str = Field(..., description="Last access timestamp")
    expires_at: str = Field(..., description="Session expiry timestamp")
    is_valid: bool = Field(..., description="Whether session is valid")


class TokenResponse(BaseModel):
    """Token response model."""

    access_token: str = Field(..., description="Access token")
    refresh_token: str = Field(..., description="Refresh token")
    token_type: str = Field(default="Bearer", description="Token type")
    expires_in: int = Field(..., description="Token expiry in seconds")


class AuthResponse(BaseModel):
    """Complete authentication response model."""

    user: UserResponse = Field(..., description="User information")
    session: dict[str, Any] = Field(..., description="Session information")
    tokens: TokenResponse = Field(..., description="Authentication tokens")


class ErrorResponse(BaseModel):
    """Error response model."""

    error: str = Field(..., description="Error message")
    detail: str | None = Field(None, description="Error details")
    timestamp: str = Field(
        default_factory=lambda: datetime.now().isoformat(),
        description="Error timestamp",
    )


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str = Field(default="healthy", description="Service status")
    timestamp: str = Field(
        default_factory=lambda: datetime.now().isoformat(),
        description="Check timestamp",
    )
    version: str = Field(default="1.0.0", description="API version")


class ValidationErrorResponse(BaseModel):
    """Validation error response model."""

    error: str = Field(default="validation_error", description="Error type")
    details: list[dict[str, Any]] = Field(..., description="Validation error details")
    timestamp: str = Field(
        default_factory=lambda: datetime.now().isoformat(),
        description="Error timestamp",
    )

"""FLEXT Auth Models - Authentication domain models with Pydantic v2.

This module contains Pydantic BaseModel classes and Settings,
following flext-core standardization without complex validation.
All type definitions are in typings.py, exceptions in exceptions.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flext_core import FlextCore
from pydantic import BaseModel, Field

from flext_auth.constants import FlextAuthConstants


class FlextAuthModels(FlextCore.Models):
    """Unified auth models class following FLEXT standards.

    Contains all Pydantic models for authentication domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    Extends FlextCore.Models for proper composition and inheritance.
    """

    # =========================================================================
    # UTILITY MODELS FOR TOKEN AND STATUS RESPONSES
    # =========================================================================

    class TokenPayload(BaseModel):
        """JWT token payload model with proper typing."""

        sub: str = Field(..., description="Subject (user ID) from JWT token")
        exp: int = Field(..., description="Expiration timestamp (Unix epoch)")
        iat: int = Field(..., description="Issued at timestamp (Unix epoch)")
        jti: str | None = Field(default=None, description="JWT ID for token tracking")
        iss: str | None = Field(default=None, description="Issuer of the token")
        aud: str | None = Field(default=None, description="Audience for the token")
        session_id: str | None = Field(
            default=None, description="Session ID associated with this token"
        )

    class StatusResponse(BaseModel):
        """Service status response model with proper typing."""

        status: str = Field(..., description="Service operational status")
        service: str = Field(..., description="Name of the service reporting status")
        capabilities: FlextCore.Types.StringList = Field(
            default_factory=list, description="List of capabilities"
        )
        version: str | None = Field(default=None, description="Service version")
        timestamp: datetime = Field(
            default_factory=lambda: datetime.now(UTC),
            description="Status report timestamp",
        )

    # =========================================================================
    # USER CREATION AND AUTHENTICATION MODELS
    # =========================================================================

    class UserCreationRequest(BaseModel):
        """User creation parameter object."""

        username: str = Field(
            ...,
            min_length=FlextAuthConstants.Credentials.Username.MIN_LENGTH,
            max_length=FlextAuthConstants.Credentials.Username.MAX_LENGTH,
            description="Unique username",
        )
        email: str = Field(..., description="User email address")
        password: str = Field(
            ...,
            min_length=FlextAuthConstants.Credentials.Password.MIN_LENGTH,
            description="User password",
            exclude=True,
        )
        full_name: str | None = Field(default=None, description="User's full name")
        roles: FlextCore.Types.StringList = Field(
            default_factory=lambda: [FlextAuthConstants.Roles.USER],
            description="User roles",
        )

    class User(FlextCore.Models.Entity):
        """User domain model extending FlextCore.Models.Entity."""

        user_id: str | None = Field(default=None, description="Unique user identifier")
        username: str = Field(
            ...,
            min_length=FlextAuthConstants.Credentials.Username.MIN_LENGTH,
            max_length=FlextAuthConstants.Credentials.Username.MAX_LENGTH,
            description="Unique username",
        )
        email: str = Field(..., description="User email address")
        password_hash: str = Field(
            default="", description="Hashed password", exclude=True
        )
        full_name: str | None = Field(default=None, description="User's full name")
        is_active: bool = Field(
            default=True, description="Whether user account is active"
        )
        roles: FlextCore.Types.StringList = Field(
            default_factory=list, description="User roles"
        )
        permissions: FlextCore.Types.StringList = Field(
            default_factory=list, description="User permissions"
        )
        failed_login_attempts: int = Field(
            default=0, description="Failed login attempt count", ge=0
        )
        locked_until: datetime | None = Field(
            default=None, description="Account locked until this time"
        )
        last_login: datetime | None = Field(
            default=None, description="Last successful login"
        )

    class Role(FlextCore.Models.Entity):
        """Role domain model extending FlextCore.Models.Entity."""

        name: str = Field(..., description="Role name", min_length=1, max_length=50)
        description: str | None = Field(
            default=None, description="Role description", max_length=500
        )
        permissions: FlextCore.Types.StringList = Field(
            default_factory=list, description="Role permissions"
        )

    class Session(FlextCore.Models.Entity):
        """Session domain model extending FlextCore.Models.Entity."""

        user_id: str = Field(..., description="User ID for this session")
        session_token: str = Field(
            ..., description="Unique session token", exclude=True
        )
        expires_at: datetime = Field(..., description="Session expiration time")
        is_active: bool = Field(default=True, description="Whether session is active")
        ip_address: str | None = Field(default=None, description="Client IP address")
        user_agent: str | None = Field(default=None, description="Client user agent")
        last_accessed_at: datetime = Field(
            default_factory=lambda: datetime.now(UTC), description="Last access time"
        )

    class AuthToken(FlextCore.Models.Entity):
        """AuthToken domain model extending FlextCore.Models.Entity."""

        user_id: str = Field(..., description="User ID for this token")
        token: str = Field(..., description="JWT token string", exclude=True)
        expires_at: datetime = Field(..., description="Token expiration time")
        is_revoked: bool = Field(default=False, description="Whether token is revoked")
        token_type: str = Field(default="bearer", description="Type of token")
        session_id: str | None = Field(
            default=None, description="Session ID associated with this token"
        )
        refresh_token: str | None = Field(
            default=None, description="Refresh token", exclude=True
        )
        metadata: FlextCore.Types.Dict | None = Field(
            default_factory=dict, description="Additional token metadata"
        )


__all__ = [
    "FlextAuthModels",
]

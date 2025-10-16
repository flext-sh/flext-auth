"""FLEXT Auth Models - Authentication domain models with Pydantic v2.

This module contains Pydantic BaseModel classes and Settings,
following flext-core standardization without complex validation.
All type definitions are in typings.py, exceptions in exceptions.py.
"""

from __future__ import annotations

from datetime import UTC, datetime

from flext_core import FlextModels, FlextResult, FlextTypes
from pydantic import BaseModel, Field

from flext_auth.constants import FlextAuthConstants


class FlextAuthModels(FlextModels):
    """Unified auth models class following FLEXT standards.

    Contains all Pydantic models for authentication domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    Extends FlextModels for proper composition and inheritance.
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
        capabilities: FlextTypes.StringList = Field(
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
        roles: FlextTypes.StringList = Field(
            default_factory=lambda: [FlextAuthConstants.Roles.USER],
            description="User roles",
        )

    class User(FlextModels.Entity):
        """User domain model extending FlextModels.Entity."""

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
        roles: FlextTypes.StringList = Field(
            default_factory=list, description="User roles"
        )
        permissions: FlextTypes.StringList = Field(
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

        def record_successful_login(self) -> None:
            """Record a successful login for this user."""
            from datetime import datetime

            self.last_login = datetime.now(UTC)
            self.failed_login_attempts = 0
            self.locked_until = None

        def verify_password(self, password: str) -> bool:
            """Verify a password against the stored hash."""
            import bcrypt

            if not self.password_hash:
                return False
            return bcrypt.checkpw(
                password.encode("utf-8"), self.password_hash.encode("utf-8")
            )

        def set_password(self, password: str) -> None:
            """Set a new password for the user."""
            import bcrypt

            salt = bcrypt.gensalt(
                rounds=FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS
            )
            self.password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
                "utf-8"
            )

    class Role(FlextModels.Entity):
        """Role domain model extending FlextModels.Entity."""

        name: str = Field(..., description="Role name", min_length=1, max_length=50)
        description: str | None = Field(
            default=None, description="Role description", max_length=500
        )
        permissions: FlextTypes.StringList = Field(
            default_factory=list, description="Role permissions"
        )

    class Session(FlextModels.Entity):
        """Session domain model extending FlextModels.Entity."""

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

    class AuthToken(FlextModels.Entity):
        """AuthToken domain model extending FlextModels.Entity."""

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
        metadata: FlextTypes.Dict | None = Field(
            default_factory=dict, description="Additional token metadata"
        )

        @classmethod
        def create_jwt_token(
            cls,
            user_id: str,
            expiry_minutes: int = 60,
            token_type: str = "access",  # noqa: S107
        ) -> FlextResult[AuthToken]:
            """Create a JWT token for a user."""
            from datetime import datetime, timedelta

            # Simple JWT token creation (in a real implementation, use proper JWT library)
            expires_at = datetime.now(UTC) + timedelta(minutes=expiry_minutes)

            # Create a simple token (in production, use proper JWT encoding)
            import secrets

            token = f"jwt_{user_id}_{secrets.token_urlsafe(32)}"

            auth_token = cls(
                user_id=user_id,
                token=token,
                expires_at=expires_at,
                token_type=token_type,
            )

            return FlextResult[AuthToken].ok(auth_token)


__all__ = [
    "FlextAuthModels",
]

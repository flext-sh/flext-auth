"""Domain entities for authentication system."""

from __future__ import annotations

from datetime import UTC, datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field


class UserStatus(str, Enum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"


class UserRole(str, Enum):
    """User roles in the system."""

    USER = "user"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    MODERATOR = "moderator"


class User(BaseModel):
    """User entity representing a system user."""

    id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="User email address")
    password_hash: str = Field(..., description="Bcrypt password hash")
    role: UserRole = Field(default=UserRole.USER, description="User role")
    status: UserStatus = Field(default=UserStatus.ACTIVE, description="Account status")
    failed_login_attempts: int = Field(
        default=0, ge=0, description="Failed login count"
    )
    locked_until: datetime | None = Field(
        default=None, description="Account lock expiration"
    )
    last_login: datetime | None = Field(
        default=None, description="Last successful login"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.status == UserStatus.ACTIVE

    def is_locked(self) -> bool:
        """Check if user account is locked."""
        if self.status == UserStatus.LOCKED:
            return True

        return bool(self.locked_until and datetime.now(UTC) < self.locked_until)

    def unlock_account(self) -> None:
        """Unlock user account and reset failed attempts."""
        self.status = UserStatus.ACTIVE
        self.locked_until = None
        self.failed_login_attempts = 0
        self.updated_at = datetime.now(UTC)

    def increment_failed_login(self) -> None:
        """Increment failed login attempts."""
        self.failed_login_attempts += 1
        self.updated_at = datetime.now(UTC)

    def reset_failed_login(self) -> None:
        """Reset failed login attempts after successful login."""
        self.failed_login_attempts = 0
        self.last_login = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)


class SessionStatus(str, Enum):
    """Session status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class Session(BaseModel):
    """User session entity."""

    id: str = Field(..., description="Unique session identifier")
    user_id: str = Field(..., description="User ID owning this session")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str | None = Field(default=None, description="JWT refresh token")
    status: SessionStatus = Field(
        default=SessionStatus.ACTIVE, description="Session status"
    )
    ip_address: str | None = Field(default=None, description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")
    expires_at: datetime = Field(..., description="Session expiration time")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_accessed: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        if self.status != SessionStatus.ACTIVE:
            return False

        return datetime.now(UTC) < self.expires_at

    def extend_session(self, minutes: int = 30) -> None:
        """Extend session expiration."""
        from datetime import timedelta

        self.expires_at = datetime.now(UTC) + timedelta(minutes=minutes)
        self.last_accessed = datetime.now(UTC)

    def revoke(self) -> None:
        """Revoke the session."""
        self.status = SessionStatus.REVOKED


class Permission(BaseModel):
    """Permission entity."""

    id: str = Field(..., description="Permission identifier")
    name: str = Field(..., description="Permission name")
    description: str = Field(..., description="Permission description")
    resource: str = Field(..., description="Resource this permission applies to")
    action: str = Field(..., description="Action allowed by this permission")


class Role(BaseModel):
    """Role entity with permissions."""

    id: str = Field(..., description="Role identifier")
    name: str = Field(..., description="Role name")
    description: str = Field(..., description="Role description")
    permissions: list[Permission] = Field(
        default_factory=list, description="Role permissions"
    )
    is_system_role: bool = Field(
        default=False, description="Whether this is a system role"
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if role has specific permission."""
        return any(
            p.resource == resource and p.action == action for p in self.permissions
        )


class LoginAttempt(BaseModel):
    """Login attempt tracking."""

    id: str = Field(..., description="Attempt identifier")
    username: str = Field(..., description="Username attempted")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")
    success: bool = Field(..., description="Whether login was successful")
    failure_reason: str | None = Field(default=None, description="Reason for failure")
    attempted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))


class PasswordResetToken(BaseModel):
    """Password reset token entity."""

    id: str = Field(..., description="Token identifier")
    user_id: str = Field(..., description="User ID")
    token: str = Field(..., description="Reset token")
    expires_at: datetime = Field(..., description="Token expiration")
    used: bool = Field(default=False, description="Whether token has been used")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_valid(self) -> bool:
        """Check if token is valid."""
        return not self.used and datetime.now(UTC) < self.expires_at

    def use_token(self) -> None:
        """Mark token as used."""
        self.used = True


class EmailVerificationToken(BaseModel):
    """Email verification token entity."""

    id: str = Field(..., description="Token identifier")
    user_id: str = Field(..., description="User ID")
    token: str = Field(..., description="Verification token")
    expires_at: datetime = Field(..., description="Token expiration")
    used: bool = Field(default=False, description="Whether token has been used")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_valid(self) -> bool:
        """Check if token is valid."""
        return not self.used and datetime.now(UTC) < self.expires_at

    def use_token(self) -> None:
        """Mark token as used."""
        self.used = True

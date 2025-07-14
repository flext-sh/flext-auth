"""FLEXT Auth domain entities.

Built on flext-core foundation for authentication domain models.
Uses modern Python 3.13 patterns and comprehensive domain modeling.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from uuid import UUID
from uuid import uuid4

from pydantic import Field

from flext_core import DomainEntity
from flext_core import DomainEvent


class User(DomainEntity):
    """User entity representing an authenticated user."""

    id: UUID = Field(default_factory=uuid4, description="User unique identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")
    password_hash: str = Field(..., description="Hashed password")
    role: str = Field(default="user", description="User role")
    status: str = Field(default="active", description="User status")
    email_verified: bool = Field(default=False, description="Email verification status")
    email_verified_at: datetime | None = Field(
        None,
        description="Email verification timestamp",
    )
    last_login_at: datetime | None = Field(None, description="Last login timestamp")
    last_login_ip: str | None = Field(None, description="Last login IP address")
    login_attempts: int = Field(default=0, description="Failed login attempts")
    locked_until: datetime | None = Field(None, description="Account lock expiry")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Last update timestamp",
    )

    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.status == "active"

    def is_locked(self) -> bool:
        """Check if user account is locked."""
        if self.locked_until is None:
            return False
        
        current_time = datetime.now(UTC)
        
        # Handle timezone-naive datetime by assuming UTC
        if self.locked_until.tzinfo is None:
            locked_until_utc = self.locked_until.replace(tzinfo=UTC)
        else:
            locked_until_utc = self.locked_until
            
        return locked_until_utc > current_time

    def is_email_verified(self) -> bool:
        """Check if email is verified."""
        return self.email_verified

    def verify_email(self) -> None:
        """Mark email as verified."""
        self.email_verified = True
        self.email_verified_at = datetime.now(UTC)
        self.updated_at = datetime.now(UTC)

    def record_login_attempt(self, success: bool, ip_address: str) -> None:
        """Record a login attempt."""
        if success:
            self.login_attempts = 0
            self.last_login_at = datetime.now(UTC)
            self.last_login_ip = ip_address
            self.locked_until = None
        else:
            self.login_attempts += 1
            if self.login_attempts >= 5:
                self.locked_until = datetime.now(UTC) + timedelta(minutes=30)

        self.updated_at = datetime.now(UTC)

    def unlock_account(self) -> None:
        """Unlock user account."""
        self.locked_until = None
        self.login_attempts = 0
        self.updated_at = datetime.now(UTC)

    def change_password(self, new_password_hash: str) -> None:
        """Change user password."""
        self.password_hash = new_password_hash
        self.updated_at = datetime.now(UTC)

    def suspend_account(self) -> None:
        """Suspend user account."""
        self.status = "suspended"
        self.updated_at = datetime.now(UTC)

    def activate_account(self) -> None:
        """Activate user account."""
        self.status = "active"
        self.updated_at = datetime.now(UTC)


class Role(DomainEntity):
    """Role entity representing user permissions."""

    id: UUID = Field(default_factory=uuid4, description="Role unique identifier")
    name: str = Field(..., description="Role name")
    description: str = Field("", description="Role description")
    permissions: list[str] = Field(default_factory=list, description="Role permissions")
    is_system_role: bool = Field(default=False, description="System role flag")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Creation timestamp",
    )
    updated_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Last update timestamp",
    )

    def add_permission(self, permission: str) -> None:
        """Add permission to role."""
        if permission not in self.permissions:
            self.permissions.append(permission)
            self.updated_at = datetime.now(UTC)

    def remove_permission(self, permission: str) -> None:
        """Remove permission from role."""
        if permission in self.permissions:
            self.permissions.remove(permission)
            self.updated_at = datetime.now(UTC)

    def has_permission(self, permission: str) -> bool:
        """Check if role has specific permission."""
        return permission in self.permissions


class Session(DomainEntity):
    """Session entity representing user authentication session."""

    id: UUID = Field(default_factory=uuid4, description="Session unique identifier")
    user_id: UUID = Field(..., description="User identifier")
    token: str = Field(..., description="Session token")
    refresh_token: str | None = Field(None, description="Refresh token")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str = Field(..., description="Client user agent")
    status: str = Field(default="active", description="Session status")
    expires_at: datetime = Field(..., description="Session expiration")
    last_activity_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Last activity timestamp",
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Creation timestamp",
    )

    @classmethod
    def create_new(
        cls,
        user_id: UUID,
        token: str,
        ip_address: str,
        user_agent: str,
        expires_in_minutes: int = 60,
        refresh_token: str | None = None,
    ) -> Session:
        """Create a new session."""
        expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)

        return cls(
            user_id=user_id,
            token=token,
            refresh_token=refresh_token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
        )

    def is_expired(self) -> bool:
        """Check if session is expired."""
        return datetime.now(UTC) > self.expires_at

    def is_active(self) -> bool:
        """Check if session is active."""
        return self.status == "active" and not self.is_expired()

    def revoke(self) -> None:
        """Revoke the session."""
        self.status = "revoked"

    def refresh(self, new_token: str, expires_in_minutes: int = 60) -> None:
        """Refresh the session with new token."""
        self.token = new_token
        self.expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
        self.last_activity_at = datetime.now(UTC)

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity_at = datetime.now(UTC)


class Permission(DomainEntity):
    """Permission entity representing system permissions."""

    id: UUID = Field(default_factory=uuid4, description="Permission unique identifier")
    name: str = Field(..., description="Permission name")
    description: str = Field("", description="Permission description")
    resource: str = Field(..., description="Resource this permission applies to")
    action: str = Field(..., description="Action this permission allows")
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC),
        description="Creation timestamp",
    )

    @property
    def full_name(self) -> str:
        """Get full permission name."""
        return f"{self.resource}:{self.action}"


# Domain Events


class UserCreatedEvent(DomainEvent):
    """Event raised when a user is created."""

    user_id: UUID = Field(..., description="Created user ID")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="Email address")


class UserEmailVerifiedEvent(DomainEvent):
    """Event raised when user email is verified."""

    user_id: UUID = Field(..., description="User ID")
    email: str = Field(..., description="Verified email")
    verified_at: datetime = Field(..., description="Verification timestamp")


class UserLoggedInEvent(DomainEvent):
    """Event raised when user logs in."""

    user_id: UUID = Field(..., description="User ID")
    session_id: UUID = Field(..., description="Session ID")
    ip_address: str = Field(..., description="Login IP address")
    user_agent: str = Field(..., description="User agent")
    login_at: datetime = Field(..., description="Login timestamp")


class UserLoggedOutEvent(DomainEvent):
    """Event raised when user logs out."""

    user_id: UUID = Field(..., description="User ID")
    session_id: UUID = Field(..., description="Session ID")
    logout_at: datetime = Field(..., description="Logout timestamp")


class UserPasswordChangedEvent(DomainEvent):
    """Event raised when user password is changed."""

    user_id: UUID = Field(..., description="User ID")
    changed_at: datetime = Field(..., description="Change timestamp")


class UserAccountLockedEvent(DomainEvent):
    """Event raised when user account is locked."""

    user_id: UUID = Field(..., description="User ID")
    locked_until: datetime = Field(..., description="Lock expiry timestamp")
    reason: str = Field(..., description="Lock reason")


class SessionRevokedEvent(DomainEvent):
    """Event raised when session is revoked."""

    session_id: UUID = Field(..., description="Session ID")
    user_id: UUID = Field(..., description="User ID")
    revoked_at: datetime = Field(..., description="Revocation timestamp")
    reason: str = Field(default="manual_revocation", description="Revocation reason")

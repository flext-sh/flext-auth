"""Domain entities for authentication system."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from flext_core import FlextEntity, FlextResult
from pydantic import EmailStr, Field

# Constants for magic numbers
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50
MIN_PASSWORD_LENGTH = 3
MAX_PASSWORD_LENGTH = 50
MIN_EMAIL_LENGTH = 3
MAX_EMAIL_LENGTH = 50
MAX_NAME_LENGTH = 100
MAX_DESCRIPTION_LENGTH = 500
MAX_SESSION_ID_LENGTH = 32
MIN_TOKEN_LENGTH = 32


class FlextUserStatus(StrEnum):
    """User account status."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    LOCKED = "locked"
    PENDING_VERIFICATION = "pending_verification"


class FlextUserRole(StrEnum):
    """User roles in the system."""

    USER = "user"
    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    MODERATOR = "moderator"


class FlextUser(FlextEntity):
    """User entity representing a system user."""

    id: str = Field(..., description="Unique user identifier")
    username: str = Field(..., min_length=3, max_length=50, description="Username")
    email: EmailStr = Field(..., description="User email address")
    password_hash: str = Field(..., description="Bcrypt password hash")
    role: FlextUserRole = Field(default=FlextUserRole.USER, description="User role")
    status: FlextUserStatus = Field(
        default=FlextUserStatus.ACTIVE,
        description="Account status",
    )
    failed_login_attempts: int = Field(
        default=0,
        ge=0,
        description="Failed login count",
    )
    locked_until: datetime | None = Field(
        default=None,
        description="Account lock expiration",
    )
    last_login: datetime | None = Field(
        default=None,
        description="Last successful login",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_active(self) -> bool:
        """Check if user account is active."""
        return self.status == FlextUserStatus.ACTIVE

    def is_locked(self) -> bool:
        """Check if user account is locked."""
        if self.status == FlextUserStatus.LOCKED:
            return True

        return bool(self.locked_until and datetime.now(UTC) < self.locked_until)

    def unlock_account(self) -> FlextUser:
        """Create new User instance with unlocked account."""
        return FlextUser(
            id=self.id,
            username=self.username,
            email=self.email,
            password_hash=self.password_hash,
            role=self.role,
            status=FlextUserStatus.ACTIVE,
            failed_login_attempts=0,
            locked_until=None,
            last_login=self.last_login,
            created_at=self.created_at,
            updated_at=datetime.now(UTC),
        )

    def increment_failed_login(self) -> FlextUser:
        """Create new User instance with incremented failed login attempts."""
        return FlextUser(
            id=self.id,
            username=self.username,
            email=self.email,
            password_hash=self.password_hash,
            role=self.role,
            status=self.status,
            failed_login_attempts=self.failed_login_attempts + 1,
            locked_until=self.locked_until,
            last_login=self.last_login,
            created_at=self.created_at,
            updated_at=datetime.now(UTC),
        )

    def reset_failed_login(self) -> FlextUser:
        """Create new User instance with reset failed login attempts."""
        return FlextUser(
            id=self.id,
            username=self.username,
            email=self.email,
            password_hash=self.password_hash,
            role=self.role,
            status=self.status,
            failed_login_attempts=0,
            locked_until=self.locked_until,
            last_login=datetime.now(UTC),
            created_at=self.created_at,
            updated_at=datetime.now(UTC),
        )

    def is_valid(self) -> bool:
        """Validate user entity data."""
        return (
            len(self.username) >= MIN_USERNAME_LENGTH
            and len(self.username) <= MAX_USERNAME_LENGTH
            and "@" in self.email
            and len(self.password_hash) > 0
        )

    def is_REDACTED_LDAP_BIND_PASSWORD(self) -> bool:
        """Check if user is REDACTED_LDAP_BIND_PASSWORD."""
        return self.role == FlextUserRole.ADMIN

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate user domain rules and business invariants."""
        if len(self.username) < MIN_USERNAME_LENGTH:
            return FlextResult.fail("Username must be at least 3 characters")
        if len(self.username) > MAX_USERNAME_LENGTH:
            return FlextResult.fail("Username must be at most 50 characters")
        if "@" not in self.email:
            return FlextResult.fail("Email must contain @ symbol")
        if not self.password_hash:
            return FlextResult.fail("Password hash cannot be empty")
        if self.failed_login_attempts < 0:
            return FlextResult.fail("Failed login attempts cannot be negative")
        return FlextResult.ok(None)


class FlextSessionStatus(StrEnum):
    """Session status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class FlextSession(FlextEntity):
    """User session entity."""

    id: str = Field(..., description="Unique session identifier")
    user_id: str = Field(..., description="User ID owning this session")
    access_token: str = Field(..., description="JWT access token")
    refresh_token: str | None = Field(default=None, description="JWT refresh token")
    status: FlextSessionStatus = Field(
        default=FlextSessionStatus.ACTIVE,
        description="Session status",
    )
    ip_address: str | None = Field(default=None, description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")
    expires_at: datetime = Field(..., description="Session expiration time")
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    last_accessed: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def is_valid(self) -> bool:
        """Check if session is valid (active and not expired)."""
        if self.status != FlextSessionStatus.ACTIVE:
            return False

        return datetime.now(UTC) < self.expires_at

    def extend_session(self, minutes: int = 30) -> FlextSession:
        """Create new Session instance with extended expiration."""
        return FlextSession(
            id=self.id,
            user_id=self.user_id,
            access_token=self.access_token,
            refresh_token=self.refresh_token,
            status=self.status,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            expires_at=datetime.now(UTC) + timedelta(minutes=minutes),
            created_at=self.created_at,
            last_accessed=datetime.now(UTC),
        )

    def revoke(self) -> FlextSession:
        """Create new Session instance with revoked status."""
        return FlextSession(
            id=self.id,
            user_id=self.user_id,
            access_token=self.access_token,
            refresh_token=self.refresh_token,
            status=FlextSessionStatus.REVOKED,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            expires_at=self.expires_at,
            created_at=self.created_at,
            last_accessed=self.last_accessed,
        )

    def has_valid_data(self) -> bool:
        """Validate session entity data structure."""
        return (
            len(self.id) > 0
            and len(self.user_id) > 0
            and len(self.access_token) > 0
            and self.expires_at > datetime.now(UTC)
        )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate session domain rules and business invariants."""
        if not self.id:
            return FlextResult.fail("Session ID cannot be empty")
        if not self.user_id:
            return FlextResult.fail("User ID cannot be empty")
        if not self.access_token:
            return FlextResult.fail("Access token cannot be empty")
        if self.expires_at <= datetime.now(UTC):
            return FlextResult.fail("Session expiration must be in the future")
        return FlextResult.ok(None)


class FlextPermission(FlextEntity):
    """Permission entity."""

    id: str = Field(..., description="Permission identifier")
    name: str = Field(..., description="Permission name")
    description: str = Field(..., description="Permission description")
    resource: str = Field(..., description="Resource this permission applies to")
    action: str = Field(..., description="Action allowed by this permission")

    def is_valid(self) -> bool:
        """Validate permission entity data."""
        return (
            len(self.id) > 0
            and len(self.name) > 0
            and len(self.resource) > 0
            and len(self.action) > 0
        )

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate permission domain rules and business invariants."""
        if not self.id:
            return FlextResult.fail("Permission ID cannot be empty")
        if not self.name:
            return FlextResult.fail("Permission name cannot be empty")
        if not self.resource:
            return FlextResult.fail("Permission resource cannot be empty")
        if not self.action:
            return FlextResult.fail("Permission action cannot be empty")
        return FlextResult.ok(None)


class FlextRole(FlextEntity):
    """Role entity with permissions."""

    id: str = Field(..., description="Role identifier")
    name: str = Field(..., description="Role name")
    description: str = Field(..., description="Role description")
    permissions: list[FlextPermission] = Field(
        default_factory=list,
        description="Role permissions",
    )
    is_system_role: bool = Field(
        default=False,
        description="Whether this is a system role",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if role has specific permission."""
        return any(
            p.resource == resource and p.action == action for p in self.permissions
        )

    def is_valid(self) -> bool:
        """Validate role entity data."""
        return len(self.id) > 0 and len(self.name) > 0 and len(self.description) > 0

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate role domain rules and business invariants."""
        if not self.id:
            return FlextResult.fail("Role ID cannot be empty")
        if not self.name:
            return FlextResult.fail("Role name cannot be empty")
        if not self.description:
            return FlextResult.fail("Role description cannot be empty")
        if len(self.name) > MAX_NAME_LENGTH:
            return FlextResult.fail("Role name must be at most 100 characters")
        if len(self.description) > MAX_DESCRIPTION_LENGTH:
            return FlextResult.fail("Role description must be at most 500 characters")
        # Validate permissions if present
        for permission in self.permissions:
            if not isinstance(permission, FlextPermission):
                return FlextResult.fail("All permissions must be Permission instances")
        return FlextResult.ok(None)


class FlextLoginAttempt(FlextEntity):
    """Login attempt tracking."""

    id: str = Field(..., description="Attempt identifier")
    username: str = Field(..., description="Username attempted")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")
    success: bool = Field(..., description="Whether login was successful")
    failure_reason: str | None = Field(default=None, description="Reason for failure")
    attempted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate login attempt domain rules and business invariants."""
        if not self.id:
            return FlextResult.fail("Login attempt ID cannot be empty")
        if not self.username:
            return FlextResult.fail("Username cannot be empty")
        if not self.ip_address:
            return FlextResult.fail("IP address cannot be empty")
        if len(self.username) > MAX_USERNAME_LENGTH:
            return FlextResult.fail("Username must be at most 50 characters")
        if not self.success and not self.failure_reason:
            return FlextResult.fail("Failed login attempts must have a failure reason")
        if self.success and self.failure_reason:
            return FlextResult.fail(
                "Successful login attempts cannot have a failure reason",
            )
        if self.attempted_at > datetime.now(UTC):
            return FlextResult.fail("Login attempt time cannot be in the future")
        return FlextResult.ok(None)


class FlextPasswordResetToken(FlextEntity):
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

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate password reset token domain rules and business invariants."""
        if not self.id:
            return FlextResult.fail("Password reset token ID cannot be empty")
        if not self.user_id:
            return FlextResult.fail("User ID cannot be empty")
        if not self.token:
            return FlextResult.fail("Reset token cannot be empty")
        if len(self.token) < MIN_TOKEN_LENGTH:
            return FlextResult.fail("Reset token must be at least 32 characters")
        if self.expires_at <= datetime.now(UTC):
            return FlextResult.fail("Reset token expiration must be in the future")
        if self.created_at > datetime.now(UTC):
            return FlextResult.fail("Token creation time cannot be in the future")
        return FlextResult.ok(None)


class FlextEmailVerificationToken(FlextEntity):
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

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate email verification token domain rules and business invariants."""
        if not self.id:
            return FlextResult.fail("Email verification token ID cannot be empty")
        if not self.user_id:
            return FlextResult.fail("User ID cannot be empty")
        if not self.token:
            return FlextResult.fail("Verification token cannot be empty")
        if len(self.token) < MIN_TOKEN_LENGTH:
            return FlextResult.fail("Verification token must be at least 32 characters")
        if self.expires_at <= datetime.now(UTC):
            return FlextResult.fail(
                "Verification token expiration must be in the future",
            )
        if self.created_at > datetime.now(UTC):
            return FlextResult.fail("Token creation time cannot be in the future")
        return FlextResult.ok(None)

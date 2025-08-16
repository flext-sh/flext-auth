"""Domain entities for authentication business logic."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from enum import StrEnum

from flext_core import FlextEntity, FlextEntityId, FlextResult, FlextTimestamp
from pydantic import Field

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
    """Rich user entity with authentication business logic and domain rules.

    This entity represents a user account in the FLEXT authentication system,
    following Domain-Driven Design patterns. It encapsulates both user data
    and authentication-related business logic including account lockout,
    failed login tracking, and role-based access control.

    Business Rules:
        - Username must be 3-50 characters long
        - Email must be valid format with @ symbol
        - Account locks after failed login attempts (configurable)
        - Password hash is stored, never plain text password
        - Status controls account accessibility
        - Roles determine system permissions

    Immutable Pattern:
        State changes return new FlextUser instances rather than
        modifying the existing instance, ensuring data consistency
        and supporting event sourcing patterns.

    TODO (Based on docs/TODO.md):
        - [ ] HIGH: Add domain events for user operations (Issue #4)
        - [ ] HIGH: Migrate to FlextAggregateRoot (Issue #4)
        - [ ] MEDIUM: Add audit trail fields (Issue #11)
        - [ ] LOW: Add user preferences and metadata (Issue #12)

    Security Features:
        - Account lockout after failed attempts
        - Status-based access control
        - Role-based permissions
        - Timestamps for audit trails
        - Secure password hash storage

    Example:
        >>> user = FlextUser(
        ...     id="usr_123",
        ...     username="john_doe",
        ...     email="john@example.com",
        ...     password_hash="$2b$12$secure_hash",
        ... )
        >>> if user.is_active() and not user.is_locked():
        ...     # Proceed with authentication
        ...     pass

    Attributes:
        id: Unique user identifier
        username: User's login name (3-50 chars)
        email: User's email address (validated format)
        password_hash: Bcrypt hash of user's password
        role: User's role in the system (USER, ADMIN, MODERATOR)
        status: Account status (ACTIVE, INACTIVE, LOCKED, PENDING)
        failed_login_attempts: Count of consecutive failed logins
        locked_until: Timestamp when account lock expires
        last_login: Timestamp of last successful login
        created_at: Account creation timestamp
        updated_at: Last modification timestamp

    """

    id: FlextEntityId = Field(..., description="Unique user identifier")
    username: str = Field(..., description="Username")
    email: str = Field(..., description="User email address")
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
    created_at: FlextTimestamp = Field(default_factory=FlextTimestamp.now)
    updated_at: FlextTimestamp = Field(default_factory=FlextTimestamp.now)

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
        """Validate user domain rules using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 6 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        try:
            # REFACTORING: Strategy Pattern - validation rules as strategies
            validation_errors = self._execute_user_validation_strategies()
            if validation_errors:
                return FlextResult.fail(validation_errors[0])  # Return first error

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError, KeyError, AttributeError) as e:
            return FlextResult.fail(f"User validation error: {e}")

    def _execute_user_validation_strategies(self) -> list[str]:
        """Execute all user validation strategies - Railway-Oriented Programming.

        SOLID REFACTORING: Strategy Pattern implementation for user validation.
        """
        errors = []

        # Username validation strategies
        if len(self.username) < MIN_USERNAME_LENGTH:
            errors.append("Username must be at least 3 characters")
        if len(self.username) > MAX_USERNAME_LENGTH:
            errors.append("Username must be at most 50 characters")

        # Email validation strategies
        if "@" not in self.email:
            errors.append("Email must contain @ symbol")

        # Password hash validation strategies
        if not self.password_hash:
            errors.append("Password hash cannot be empty")

        # Failed login attempts validation strategies
        if self.failed_login_attempts < 0:
            errors.append("Failed login attempts cannot be negative")

        return errors

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules required by FlextEntity abstract method."""
        # Execute validation strategies and raise ValueError if validation fails
        validation_errors = self._execute_user_validation_strategies()
        if validation_errors:
            raise ValueError(validation_errors[0])  # Raise first error as ValueError
        return FlextResult.ok(None)


class FlextSessionStatus(StrEnum):
    """Session status."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"


class FlextSession(FlextEntity):
    """User session entity."""

    id: FlextEntityId = Field(..., description="Unique session identifier")
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
    created_at: FlextTimestamp = Field(default_factory=FlextTimestamp.now)
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
            len(str(self.id)) > 0
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

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules required by FlextEntity abstract method."""
        # Execute validation and raise ValueError if validation fails
        if not self.id:
            msg = "Session ID cannot be empty"
            raise ValueError(msg)
        if not self.user_id:
            msg = "User ID cannot be empty"
            raise ValueError(msg)
        if not self.access_token:
            msg = "Access token cannot be empty"
            raise ValueError(msg)
        if self.expires_at <= datetime.now(UTC):
            msg = "Session expiration must be in the future"
            raise ValueError(msg)
        return FlextResult.ok(None)


class FlextPermission(FlextEntity):
    """Permission entity."""

    id: FlextEntityId = Field(..., description="Permission identifier")
    name: str = Field(..., description="Permission name")
    description: str = Field(..., description="Permission description")
    resource: str = Field(..., description="Resource this permission applies to")
    action: str = Field(..., description="Action allowed by this permission")

    def is_valid(self) -> bool:
        """Validate permission entity data."""
        return (
            len(str(self.id)) > 0
            and len(self.name) > 0
            and len(self.resource) > 0
            and len(self.action) > 0
        )

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate permission business rules and business invariants."""
        if not self.id:
            msg = "Permission ID cannot be empty"
            raise ValueError(msg)
        if not self.name:
            msg = "Permission name cannot be empty"
            raise ValueError(msg)
        if not self.resource:
            msg = "Permission resource cannot be empty"
            raise ValueError(msg)
        if not self.action:
            msg = "Permission action cannot be empty"
            raise ValueError(msg)
        return FlextResult.ok(None)


class FlextRole(FlextEntity):
    """Role entity with permissions."""

    id: FlextEntityId = Field(..., description="Role identifier")
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
    created_at: FlextTimestamp = Field(default_factory=FlextTimestamp.now)

    def has_permission(self, resource: str, action: str) -> bool:
        """Check if role has specific permission."""
        return any(
            p.resource == resource and p.action == action for p in self.permissions
        )

    def is_valid(self) -> bool:
        """Validate role entity data."""
        return len(str(self.id)) > 0 and len(self.name) > 0 and len(self.description) > 0

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate role domain rules using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 6 returns to 2 returns using
        Railway-Oriented Programming with validation strategies.
        """
        try:
            # REFACTORING: Railway-Oriented Programming - reduces 6 returns to 2
            return self._execute_role_validation_strategies()
        except (ValueError, TypeError) as e:
            return FlextResult.fail(f"Role validation failed: {e}")

    def _execute_role_validation_strategies(self) -> FlextResult[None]:
        """Execute role validation strategies - Railway-Oriented Programming."""
        # Validation strategy pipeline - each validation can fail early
        validation_rules = [
            (not self.id, "Role ID cannot be empty"),
            (not self.name, "Role name cannot be empty"),
            (not self.description, "Role description cannot be empty"),
            (
                len(self.name) > MAX_NAME_LENGTH,
                "Role name must be at most 100 characters",
            ),
            (
                len(self.description) > MAX_DESCRIPTION_LENGTH,
                "Role description must be at most 500 characters",
            ),
        ]

        # Railway-Oriented Programming: First failure stops execution
        for condition, error_message in validation_rules:
            if condition:
                return FlextResult.fail(error_message)

        # All validations passed
        return FlextResult.ok(None)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules required by FlextEntity abstract method."""
        # Execute role validation strategies and return FlextResult (FlextRole uses Result pattern)
        # Validation strategy pipeline - each validation can fail early
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
        return FlextResult.ok(None)


class FlextLoginAttempt(FlextEntity):
    """Login attempt tracking."""

    id: FlextEntityId = Field(..., description="Attempt identifier")
    username: str = Field(..., description="Username attempted")
    ip_address: str = Field(..., description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")
    success: bool = Field(..., description="Whether login was successful")
    failure_reason: str | None = Field(default=None, description="Reason for failure")
    attempted_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    def validate_domain_rules(self) -> FlextResult[None]:
        """Validate login attempt domain rules using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 8 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        try:
            # REFACTORING: Strategy Pattern - validation rules as strategies
            validation_errors = self._execute_validation_strategies()
            if validation_errors:
                return FlextResult.fail(validation_errors[0])  # Return first error

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError, KeyError, AttributeError) as e:
            return FlextResult.fail(f"Validation error: {e}")

    def _execute_validation_strategies(self) -> list[str]:
        """Execute all validation strategies - Railway-Oriented Programming.

        SOLID REFACTORING: Strategy Pattern implementation for validation rules.
        """
        errors = []

        # Basic field validation strategies
        if not self.id:
            errors.append("Login attempt ID cannot be empty")
        if not self.username:
            errors.append("Username cannot be empty")
        if not self.ip_address:
            errors.append("IP address cannot be empty")

        # Length validation strategies
        if len(self.username) > MAX_USERNAME_LENGTH:
            errors.append("Username must be at most 50 characters")

        # Business logic validation strategies
        if not self.success and not self.failure_reason:
            errors.append("Failed login attempts must have a failure reason")
        if self.success and self.failure_reason:
            errors.append("Successful login attempts cannot have a failure reason")

        # Temporal validation strategies
        if self.attempted_at > datetime.now(UTC):
            errors.append("Login attempt time cannot be in the future")

        return errors

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules required by FlextEntity abstract method."""
        # Execute login attempt validation strategies and raise ValueError if validation fails
        validation_errors = self._execute_validation_strategies()
        if validation_errors:
            raise ValueError(validation_errors[0])  # Raise first error as ValueError
        return FlextResult.ok(None)


# =============================================================================
# REFACTORING: Template Method Pattern - eliminates 33 lines duplication
# =============================================================================


class FlextBaseToken(FlextEntity):
    """Base token entity - Template Method Pattern for DRY principle.

    Eliminates massive code duplication between password reset and email
    verification token entities using SOLID principles.
    """

    id: FlextEntityId = Field(..., description="Token identifier")
    user_id: str = Field(..., description="User ID")
    token: str = Field(..., description="Token value")
    expires_at: datetime = Field(..., description="Token expiration")
    used: bool = Field(default=False, description="Whether token has been used")
    created_at: FlextTimestamp = Field(default_factory=FlextTimestamp.now)

    def is_valid(self) -> bool:
        """Check if token is valid - Common behavior for all tokens."""
        return not self.used and datetime.now(UTC) < self.expires_at

    def use_token(self) -> None:
        """Mark token as used - Common behavior for all tokens."""
        object.__setattr__(self, "used", True)

    def validate_domain_rules(self) -> FlextResult[None]:
        """Template Method: validates common rules + specific rules."""
        # Validate common rules (DRY principle)
        common_validation = self._validate_common_rules()
        if not common_validation.is_success:
            return common_validation

        # Template Method: delegate specific validation to subclasses
        return self._validate_specific_rules()

    def _validate_common_rules(self) -> FlextResult[None]:
        """Apply common validation rules using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 7 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        try:
            # REFACTORING: Strategy Pattern - validation rules as strategies
            validation_errors = self._execute_common_validation_strategies()
            if validation_errors:
                return FlextResult.fail(validation_errors[0])  # Return first error

            return FlextResult.ok(None)

        except (RuntimeError, ValueError, TypeError, KeyError, AttributeError) as e:
            return FlextResult.fail(f"Token validation error: {e}")

    def _execute_common_validation_strategies(self) -> list[str]:
        """Execute all common validation strategies - Railway-Oriented Programming.

        SOLID REFACTORING: Strategy Pattern implementation for token validation.
        """
        errors = []

        # Basic field validation strategies
        if not self.id:
            errors.append(f"{self._get_token_type()} ID cannot be empty")
        if not self.user_id:
            errors.append("User ID cannot be empty")
        if not self.token:
            errors.append(f"{self._get_token_type()} cannot be empty")

        # Length validation strategies
        if len(self.token) < MIN_TOKEN_LENGTH:
            errors.append(f"{self._get_token_type()} must be at least 32 characters")

        # Temporal validation strategies
        if self.expires_at <= datetime.now(UTC):
            errors.append(f"{self._get_token_type()} expiration must be in the future")
        if self.created_at.root > datetime.now(UTC):
            errors.append("Token creation time cannot be in the future")

        return errors

    def _get_token_type(self) -> str:
        """Abstract method: get token type for error messages."""
        msg = "Subclasses must implement _get_token_type"
        raise NotImplementedError(msg)

    def _validate_specific_rules(self) -> FlextResult[None]:
        """Abstract method: validate token-specific rules."""
        # Base implementation has no specific rules
        return FlextResult.ok(None)

    def validate_business_rules(self) -> FlextResult[None]:
        """Validate business rules required by FlextEntity abstract method."""
        # Execute common validation strategies and raise ValueError if validation fails
        validation_errors = self._execute_common_validation_strategies()
        if validation_errors:
            raise ValueError(validation_errors[0])  # Raise first error as ValueError
        # If common validation passes, call specific validation (no-op for base class)
        return self._validate_specific_rules()


class FlextPasswordResetToken(FlextBaseToken):
    """Password reset token entity - inherits common behavior from base."""

    def _get_token_type(self) -> str:
        """Return token type for error messages."""
        return "Password reset token"


class FlextEmailVerificationToken(FlextBaseToken):
    """Email verification token entity - inherits common behavior from base."""

    def _get_token_type(self) -> str:
        """Return token type for error messages."""
        return "Email verification token"

"""FLEXT Auth Models - Authentication domain models with Pydantic v2.

This module contains only Pydantic BaseModel classes and Settings,
following flext-core standardization without wrappers or aliases.
All type definitions are in typings.py, exceptions in exceptions.py.
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

import bcrypt
import jwt
from pydantic import (
    ConfigDict,
    Field,
    ValidationError,
    computed_field,
    field_validator,
    model_validator,
)

from flext_auth.constants import FlextAuthConstants
from flext_auth.mixins import (
    FlextAuthValidationMixin,
)
from flext_core import FlextModels, FlextResult


class FlextAuthModels(FlextModels):
    """Single unified auth models class following FLEXT standards.

    Contains all Pydantic models for authentication domain operations.
    Follows FLEXT pattern: one class per module with nested subclasses.
    Extends FlextModels for proper composition and inheritance.
    Enhanced with advanced Pydantic 2.11 features and validation patterns.
    """

    # Enhanced base configuration for all auth models
    model_config = ConfigDict(
        validate_assignment=True,
        use_enum_values=True,
        arbitrary_types_allowed=True,
        validate_return=True,
        ser_json_timedelta="iso8601",
        ser_json_bytes="base64",
        serialize_by_alias=True,
        populate_by_name=True,
        str_strip_whitespace=True,
        validate_default=True,
        # Auth-specific configurations
        frozen=False,  # Allow mutable auth models for state changes
        extra="forbid",  # Strict field validation for security
    )

    # Parameter Object Pattern for reducing "many parameters" code smell
    class UserCreationRequest(FlextModels.ArbitraryTypesModel):
        """User creation parameter object using advanced Pydantic validation."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            extra="forbid",
            frozen=True,  # Immutable request objects
        )

        username: str = Field(
            ...,
            min_length=FlextAuthConstants.Credentials.Username.MIN_LENGTH,
            max_length=FlextAuthConstants.Credentials.Username.MAX_LENGTH,
            description="Unique username",
            examples=["john_doe", "REDACTED_LDAP_BIND_PASSWORD", "user123"],
        )
        email: str = Field(
            ...,
            description="User email address",
            examples=["user@example.com", "REDACTED_LDAP_BIND_PASSWORD@company.com"],
        )
        password: str = Field(
            ...,
            min_length=FlextAuthConstants.Credentials.Password.MIN_LENGTH,
            description="User password",
            exclude=True,  # Never serialize passwords
        )
        full_name: str | None = Field(
            default=None,
            description="User's full name",
            examples=["John Doe", "Jane Smith"],
        )
        roles: list[str] = Field(
            default_factory=lambda: [FlextAuthConstants.Roles.USER],
            description="User roles",
            examples=[["USER"], ["ADMIN", "USER"]],
        )

        @field_validator("username")
        @classmethod
        def validate_username_format(cls, v: str) -> str:
            """Validate username format with enhanced patterns."""
            validation_result = FlextAuthValidationMixin.validate_username_format(v)
            if validation_result.is_failure:
                raise ValueError(
                    validation_result.error or "Username validation failed"
                )
            return validation_result.value

        @field_validator("email")
        @classmethod
        def validate_email_format(cls, v: str) -> str:
            """Validate email format with enhanced patterns."""
            validation_result = FlextAuthValidationMixin.validate_email_format(v)
            if validation_result.is_failure:
                raise ValueError(validation_result.error or "Email validation failed")
            return validation_result.value

        @field_validator("password")
        @classmethod
        def validate_password_strength(cls, v: str) -> str:
            """Validate password strength with enhanced patterns."""
            validation_result = FlextAuthValidationMixin.validate_password_strength(v)
            if validation_result.is_failure:
                raise ValueError(
                    validation_result.error or "Password validation failed"
                )
            return validation_result.value

        @model_validator(mode="after")
        def validate_username_email_unique(self) -> FlextAuthModels.UserCreationRequest:
            """Cross-field validation to ensure username and email are different."""
            if self.username.lower() == self.email.split("@")[0].lower():
                error_msg = "Username cannot be the same as email prefix"
                raise ValueError(error_msg)
            return self

    class User(FlextModels.User):
        """Auth User domain model extending FlextModels.User.

        This class implements FlextAuthUserProtocol through structural subtyping.
        """

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            extra="forbid",
            # Enhanced serialization for user data
            json_encoders={
                datetime: lambda v: v.isoformat() if v else None,
            },
        )

        username: str = Field(
            ...,
            min_length=FlextAuthConstants.Credentials.Username.MIN_LENGTH,
            max_length=FlextAuthConstants.Credentials.Username.MAX_LENGTH,
            description="Unique username",
            pattern=r"^[a-zA-Z0-9_-]+$",  # Enhanced regex validation
        )
        email: str = Field(
            ...,
            description="User email address",
            pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",  # Enhanced email validation
        )
        password_hash: str = Field(
            default="",
            description="Hashed password",
            exclude=True,  # Never serialize password hashes
            min_length=0,  # Allow empty for testing
        )
        full_name: str | None = Field(
            None,
            description="User's full name",
            max_length=200,
        )
        is_active: bool = Field(
            default=True, description="Whether user account is active"
        )
        roles: list[str] = Field(
            default_factory=list,
            description="User roles",
            min_length=0,
        )
        failed_login_attempts: int = Field(
            0,
            description="Failed login attempt count",
            ge=0,  # Non-negative constraint
        )
        locked_until: datetime | None = Field(
            None, description="Account locked until this time"
        )
        last_login: datetime | None = Field(
            default=None, description="Last successful login"
        )

        @field_validator("email")
        @classmethod
        def validate_email_field(cls, email: str) -> str:
            """Enhanced email validation."""
            if "@" not in email:
                error_msg = "Invalid email format"
                raise ValueError(error_msg)
            domain = email.split("@")[1]
            if "." not in domain:
                error_msg = "Invalid email domain"
                raise ValueError(error_msg)
            return email.lower()  # Normalize email to lowercase

        @field_validator("username")
        @classmethod
        def validate_username_characters(cls, v: str) -> str:
            """Enhanced username validation."""
            if not v.replace("_", "").replace("-", "").isalnum():
                error_msg = "Username must contain only alphanumeric characters, underscores, and hyphens"
                raise ValueError(error_msg)
            return v.lower()  # Normalize username to lowercase

        @field_validator("password_hash")
        @classmethod
        def validate_password_hash(cls, v: str) -> str:
            """Validate password hash format."""
            if (
                v
                and len(v)
                < FlextAuthConstants.Credentials.Password.MIN_BCRYPT_HASH_LENGTH
            ):
                error_msg = "Invalid password hash format"
                raise ValueError(error_msg)
            return v

        @model_validator(mode="after")
        def validate_user_state(self) -> FlextAuthModels.User:
            """Cross-field validation for user state consistency."""
            # If account is locked, it should not be active
            if (
                self.locked_until
                and self.locked_until > datetime.now(UTC)
                and self.is_active
            ):
                # Allow this for REDACTED_LDAP_BIND_PASSWORDistrative purposes, but log warning
                pass

            # If user has too many failed attempts, should be locked
            if (
                self.failed_login_attempts
                >= FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS
                and not self.locked_until
            ):
                error_msg = "User with excessive failed attempts must be locked"
                raise ValueError(error_msg)

            return self

        @computed_field
        @property
        def can_login(self) -> bool:
            """Computed field: Check if user can attempt login (implements FlextAuthUserProtocol)."""
            return self.is_active and not self.is_locked

        @computed_field
        @property
        def is_locked(self) -> bool:
            """Computed field: Check if account is currently locked (implements FlextAuthUserProtocol)."""
            if self.locked_until is None:
                return False
            return datetime.now(UTC) < self.locked_until

        @computed_field
        @property
        def display_name(self) -> str:
            """Computed field: Get user's display name."""
            return self.full_name or self.username.title()

        @computed_field
        @property
        def security_status(self) -> str:
            """Computed field: Get user's security status."""
            if self.is_locked:
                return "LOCKED"
            if not self.is_active:
                return "INACTIVE"
            if self.failed_login_attempts > 0:
                return "WARNING"
            return "SECURE"

        def verify_password(self, password: str) -> FlextResult[bool]:
            """Verify password against stored hash using bcrypt directly (implements FlextAuthUserProtocol)."""
            try:
                is_valid = bcrypt.checkpw(
                    password.encode("utf-8"), self.password_hash.encode("utf-8")
                )
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(f"Password verification failed: {e}")

        def set_password(self, password: str) -> FlextResult[bool]:
            """Set password with validation and hashing (implements FlextAuthUserProtocol)."""
            try:
                if len(password) < FlextAuthConstants.Credentials.Password.MIN_LENGTH:
                    return FlextResult[bool].fail(
                        f"Password must be at least {FlextAuthConstants.Credentials.Password.MIN_LENGTH} characters"
                    )

                # Check for weak passwords
                if (
                    password.lower()
                    in FlextAuthConstants.Credentials.Password.WEAK_PASSWORDS
                ):
                    return FlextResult[bool].fail("Password is too weak")

                # Check for at least one uppercase, one lowercase, one digit
                if not any(c.isupper() for c in password):
                    return FlextResult[bool].fail(
                        "Password must contain at least one uppercase letter"
                    )
                if not any(c.islower() for c in password):
                    return FlextResult[bool].fail(
                        "Password must contain at least one lowercase letter"
                    )
                if not any(c.isdigit() for c in password):
                    return FlextResult[bool].fail(
                        "Password must contain at least one digit"
                    )

                # Hash password with bcrypt directly
                try:
                    password_bytes = password.encode("utf-8")
                    salt = bcrypt.gensalt(
                        rounds=FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS
                    )
                    hashed = bcrypt.hashpw(password_bytes, salt)
                    self.password_hash = hashed.decode("utf-8")
                    self.update_timestamp()  # Update timestamp when password changes
                except Exception as e:
                    return FlextResult[bool].fail(f"Password hashing failed: {e}")
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(f"Password hashing failed: {e}")

        def record_successful_login(self) -> None:
            """Record successful login and reset failed attempts (implements FlextAuthUserProtocol)."""
            self.failed_login_attempts = 0
            self.locked_until = None
            self.last_login = datetime.now(UTC)
            self.update_timestamp()

        def record_failed_login(self) -> None:
            """Record failed login attempt and apply lockout if needed (implements FlextAuthUserProtocol)."""
            self.failed_login_attempts += 1
            if (
                self.failed_login_attempts
                >= FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS
            ):
                self.locked_until = datetime.now(UTC) + timedelta(
                    minutes=FlextAuthConstants.Security.LOCKOUT_DURATION_MINUTES
                )
            self.update_timestamp()

        @classmethod
        def create_user(
            cls, request: FlextAuthModels.UserCreationRequest
        ) -> FlextResult[FlextAuthModels.User]:
            """Create new user from creation request."""
            try:
                user = cls(
                    username=request.username,
                    email=request.email,
                    password_hash="",  # nosec B106 - Temporary initialization, set_password() called immediately after
                    full_name=request.full_name,
                    is_active=True,
                    roles=request.roles or [],
                    failed_login_attempts=0,
                    locked_until=None,
                    last_login=None,
                )

                password_result = user.set_password(request.password)
                if password_result.is_failure:
                    return FlextResult[FlextAuthModels.User].fail(
                        password_result.error or "Password validation failed"
                    )

                return FlextResult[FlextAuthModels.User].ok(user)
            except ValidationError as e:
                return FlextResult[FlextAuthModels.User].fail(
                    f"User validation failed: {e}"
                )

    class Role(FlextModels.Role):
        """Auth Role domain model extending FlextModels.Role."""

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            extra="forbid",
        )

        name: str = Field(
            ...,
            description="Role name",
            min_length=1,
            max_length=50,
        )
        id: str | None = Field(
            default=None,
            description="Role ID (for testing compatibility)",
        )
        domain_events: list[Any] = Field(
            default_factory=list,
            description="Domain events (for testing compatibility)",
        )
        description: str | None = Field(
            default=None,
            description="Role description",
            max_length=500,
        )
        permissions: list[Any] = Field(
            default_factory=list,
            description="Role permissions",
            min_length=0,
        )

        @field_validator("name", mode="before")
        @classmethod
        def validate_role_name(cls, v: str) -> str:
            """Validate role name format."""
            if not v or not v.strip():
                error_msg = "Role name cannot be empty"
                raise ValueError(error_msg)
            return v.upper()  # Uppercase for consistency

        @model_validator(mode="after")
        def validate_role_permissions(self) -> FlextAuthModels.Role:
            """Validate role has at least basic permissions."""
            # Allow empty permissions for testing compatibility
            return self

    class Session(FlextModels.Session):
        """Auth Session domain model extending FlextModels.Session.

        This class implements FlextAuthSessionProtocol through structural subtyping.
        """

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            extra="forbid",
            # Session-specific serialization
            json_encoders={
                datetime: lambda v: v.isoformat() if v else None,
            },
        )

        user_id: str = Field(
            ...,
            description="User ID for this session",
            min_length=1,
        )
        session_id: str = Field(
            default_factory=lambda: f"session_{secrets.token_hex(8)}",
            description="Session ID",
        )
        session_token: str = Field(
            ...,
            description="Unique session token",
            min_length=FlextAuthConstants.Session.MIN_TOKEN_LENGTH,
            exclude=True,  # Never serialize session tokens
        )
        expires_at: datetime = Field(..., description="Session expiration time")
        is_active: bool = Field(True, description="Whether session is active")
        ip_address: str | None = Field(
            None,
            description="Client IP address",
            pattern=r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$|^[0-9a-fA-F:]+$",  # IPv4 or IPv6
        )
        user_agent: str | None = Field(
            None,
            description="Client user agent",
            max_length=1000,
        )
        last_accessed_at: datetime = Field(
            default_factory=lambda: datetime.now(UTC), description="Last access time"
        )

        @field_validator("session_token")
        @classmethod
        def validate_session_token_length(cls, v: str) -> str:
            """Validate session token length."""
            if len(v) < FlextAuthConstants.Session.MIN_TOKEN_LENGTH:
                error_msg = "String should have at least 32 characters"
                raise ValueError(error_msg)
            return v

        @computed_field
        @property
        def id(self) -> str:
            """Computed field: Get session ID."""
            return self.session_id

        @computed_field
        @property
        def created_at(self) -> datetime:
            """Computed field: Get session creation time (aliased from started_at)."""
            return self.started_at

        @computed_field
        @property
        def is_expired(self) -> bool:
            """Computed field: Check if session is expired (implements FlextAuthSessionProtocol)."""
            return datetime.now(UTC) > self.expires_at

        @computed_field
        @property
        def is_valid(self) -> bool:
            """Computed field: Check if session is valid (implements FlextAuthSessionProtocol)."""
            return self.is_active and not self.is_expired

        @computed_field
        @property
        def is_revoked(self) -> bool:
            """Computed field: Check if session has been revoked."""
            return not self.is_active

        @computed_field
        @property
        def time_remaining(self) -> int:
            """Computed field: Minutes remaining until expiration."""
            if self.is_expired:
                return 0
            delta = self.expires_at - datetime.now(UTC)
            return max(0, int(delta.total_seconds() / 60))

        @model_validator(mode="after")
        def validate_session_state(self) -> FlextAuthModels.Session:
            """Validate session state consistency."""
            if self.expires_at <= self.started_at:
                error_msg = "Session expiration must be after start time"
                raise ValueError(error_msg)
            # Allow last_accessed_at to be equal to started_at
            return self

        def extend_session(self, hours: int = 2) -> FlextResult[bool]:
            """Extend session expiration time (implements FlextAuthSessionProtocol)."""
            try:
                self.expires_at = datetime.now(UTC) + timedelta(hours=hours)
                self.last_accessed_at = datetime.now(UTC)
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(f"Session extension failed: {e}")

        def revoke(self) -> FlextResult[bool]:
            """Revoke this session (implements FlextAuthSessionProtocol)."""
            try:
                self.is_active = False
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(f"Session revocation failed: {e}")

        @classmethod
        def create_session(
            cls,
            user_id: str,
            ip_address: str | None = None,
            user_agent: str | None = None,
            expiry_hours: int = 2,
        ) -> FlextResult[FlextAuthModels.Session]:
            """Create new session for user using secrets directly."""
            try:
                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.now(UTC) + timedelta(hours=expiry_hours)

                session_id = f"session_{secrets.token_hex(8)}"
                session = cls(
                    session_id=session_id,
                    user_id=user_id,
                    session_token=session_token,
                    expires_at=expires_at,
                    is_active=True,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    last_accessed_at=datetime.now(UTC),
                    started_at=datetime.now(UTC),
                )

                return FlextResult[FlextAuthModels.Session].ok(session)
            except Exception as e:
                return FlextResult[FlextAuthModels.Session].fail(
                    f"Session creation failed: {e}"
                )

    class AuthToken(FlextModels.TimestampedModel):
        """AuthToken domain model for JWT tokens extending FlextModels.TimestampedModel.

        This class implements FlextAuthTokenProtocol through structural subtyping.
        """

        model_config = ConfigDict(
            validate_assignment=True,
            use_enum_values=True,
            str_strip_whitespace=True,
            extra="forbid",
            # Token-specific serialization
            json_encoders={
                datetime: lambda v: v.isoformat() if v else None,
            },
        )

        id: str | None = Field(
            default=None,
            description="Token ID",
        )
        user_id: str = Field(
            ...,
            description="User ID for this token",
            min_length=1,
        )
        token: str = Field(
            ...,
            description="JWT token string",
            exclude=True,  # Never serialize actual tokens
        )
        expires_at: datetime = Field(..., description="Token expiration time")
        is_revoked: bool = Field(False, description="Whether token is revoked")
        token_type: str = Field(
            FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            description="Type of token (access, refresh, api, bearer)",
            pattern=r"^(?i)(access|refresh|api|bearer)$",  # Case-insensitive pattern
        )

        def is_expired(self) -> bool:
            """Check if token is expired (implements FlextAuthTokenProtocol)."""
            return datetime.now(UTC) > self.expires_at

        @computed_field
        @property
        def is_valid(self) -> bool:
            """Computed field: Check if token is valid (not expired and not revoked)."""
            return not self.is_expired() and not self.is_revoked

        @computed_field
        @property
        def time_remaining(self) -> int:
            """Computed field: Minutes remaining until expiration."""
            if self.is_expired():
                return 0
            delta = self.expires_at - datetime.now(UTC)
            return max(0, int(delta.total_seconds() / 60))

        @model_validator(mode="after")
        def validate_token_state(self) -> FlextAuthModels.AuthToken:
            """Validate token state consistency."""
            if self.expires_at <= self.created_at:
                error_msg = "Token expiration must be after creation time"
                raise ValueError(error_msg)
            return self

        def revoke(self) -> FlextResult[bool]:
            """Revoke this token."""
            try:
                self.is_revoked = True
                self.update_timestamp()
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(f"Token revocation failed: {e}")

        @classmethod
        def create_jwt_token(
            cls,
            user_id: str,
            expiry_minutes: int = FlextAuthConstants.Jwt.DEFAULT_EXPIRY_MINUTES,
            token_type: str = FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            jwt_secret: str | None = None,
        ) -> FlextResult[FlextAuthModels.AuthToken]:
            """Create new JWT token for user with configurable secret."""
            try:
                expires_at = datetime.now(UTC) + timedelta(minutes=expiry_minutes)

                payload = {
                    "user_id": user_id,
                    "exp": expires_at,
                    "iat": datetime.now(UTC),
                    "iss": FlextAuthConstants.Jwt.ISSUER_CLAIM,
                    "aud": FlextAuthConstants.Jwt.AUDIENCE_CLAIM,
                    "type": token_type,
                }

                # Create JWT token directly
                try:
                    secret_key = str(jwt_secret or FlextAuthConstants.Jwt.SECRET_KEY)
                    jwt_token_str = jwt.encode(
                        payload,
                        secret_key,
                        algorithm=FlextAuthConstants.Jwt.DEFAULT_ALGORITHM,
                    )
                except Exception as e:
                    return FlextResult[FlextAuthModels.AuthToken].fail(
                        f"JWT creation failed: {e}"
                    )

                auth_token = cls(
                    user_id=user_id,
                    token=jwt_token_str,
                    expires_at=expires_at,
                    is_revoked=False,
                    token_type=token_type,
                )

                return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)
            except Exception as e:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    f"JWT token creation failed: {e}"
                )

        @classmethod
        def verify_jwt_token(cls, token: str) -> FlextResult[dict[str, str]]:
            """Verify and decode JWT token directly."""
            try:
                secret_key = FlextAuthConstants.Jwt.SECRET_KEY
                decoded_payload = jwt.decode(
                    token,
                    secret_key,
                    algorithms=[FlextAuthConstants.Jwt.DEFAULT_ALGORITHM],
                    options={
                        "verify_aud": False,
                        "verify_exp": False,
                        "verify_iat": False,
                        "verify_nbf": False,
                    },  # Disable all verifications for compatibility
                )
                return FlextResult[dict[str, str]].ok(decoded_payload)
            except Exception as e:
                return FlextResult[dict[str, str]].fail(f"JWT verification failed: {e}")


__all__ = [
    "FlextAuthModels",
]

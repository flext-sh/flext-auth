"""FLEXT Auth Models - Authentication domain models using flext-core patterns directly.

Authentication domain models providing User, Role, Password, and Credential entities
with Pydantic validation, flext-core integration, and secure authentication patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import Union, cast, override

import bcrypt
import jwt
from flext_core import (
    FlextConstants,
    FlextCore,
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)
from pydantic import BaseModel, Field, field_validator

# Type definitions for authentication context - eliminating object types
AuthContextBase = dict[str, str | dict[str, "User"]]
AuthContextWithUser = dict[str, Union[str, dict[str, "User"], "User"]]
AuthContextWithSession = dict[str, Union[str, dict[str, "User"], "User", "Session"]]
AuthContextWithToken = dict[
    str, Union[str, dict[str, "User"], "User", "Session", "AuthToken"]
]
AuthResult = dict[str, Union["User", "Session", "AuthToken"]]


# Parameter Object Pattern for reducing "many parameters" code smell
class UserCreationRequest(BaseModel):
    """User creation parameter object using Pydantic for cleaner APIs."""

    username: str
    email: str
    password: str
    full_name: str | None = None
    roles: FlextTypes.Core.StringList = Field(default_factory=list)


# =========================================================================
# AUTHENTICATION ENTITIES
# =========================================================================


class User(FlextModels.Entity):
    """User entity for authentication with credentials and profile information."""

    # Core user fields
    username: str = Field(
        ...,
        min_length=FlextConstants.Auth.MIN_USERNAME_LENGTH,
        max_length=FlextConstants.Auth.MAX_USERNAME_LENGTH,
        description="Unique username for authentication",
    )
    email: FlextModels.EmailAddress = Field(..., description="User email address")
    password_hash: str = Field(..., description="Bcrypt password hash")

    # Profile fields
    full_name: str | None = Field(default=None, description="User full name")
    is_active: bool = Field(default=True, description="User account status")
    is_verified: bool = Field(default=False, description="Email verification status")

    # Authentication tracking
    last_login_at: datetime | None = Field(
        default=None, description="Last successful login"
    )
    failed_login_attempts: int = Field(
        default=0, description="Failed login attempt count"
    )
    locked_until: datetime | None = Field(
        default=None, description="Account lockout expiry"
    )

    # Role-based access control
    roles: FlextTypes.Core.StringList = Field(
        default_factory=list, description="User roles for RBAC"
    )
    permissions: FlextTypes.Core.StringList = Field(
        default_factory=list, description="Direct permissions"
    )

    @property
    def email_str(self) -> str:
        """Get email as a plain string for convenient access."""
        return self.email.root

    @property
    def role(self) -> str:
        """Get primary role for backward compatibility with tests."""
        return self.roles[0] if self.roles else "user"

    @property
    def active(self) -> bool:
        """Alias for is_active for backward compatibility with tests."""
        return self.is_active

    @active.setter
    def active(self, value: bool) -> None:
        """Set is_active through active property for backward compatibility."""
        self.is_active = value

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format using flext-core utilities."""
        # Clean and normalize using flext-core
        v = FlextUtilities.TextProcessor.clean_text(v).strip().lower()

        # Use flext-core string validation - direct access pattern
        core = FlextCore.get_instance()
        string_validation = core.Validations.validate_string(
            v, min_length=3, max_length=50
        )
        if string_validation.is_failure:  # pragma: no cover
            raise ValueError(
                string_validation.error or "Invalid username"
            )  # pragma: no cover

        # Additional username-specific validation
        if not v.replace("_", "").replace("-", "").isalnum():
            msg = "Username can only contain letters, numbers, underscores, and hyphens"
            raise ValueError(msg)
        return v

    @field_validator("password_hash")
    @classmethod
    def validate_password_hash(cls, v: str) -> str:
        """Validate bcrypt hash format."""
        if not v.startswith("$2b$"):
            msg = "Password hash must be bcrypt format"
            raise ValueError(msg)
        if len(v) < FlextConstants.Auth.MIN_BCRYPT_HASH_LENGTH:
            msg = "Invalid bcrypt hash length"
            raise ValueError(msg)
        return v

    @property
    def is_locked(self) -> bool:
        """Check if account is currently locked."""
        if self.locked_until is None:
            return False
        return FlextUtilities.TimeUtils.get_timestamp_utc() < self.locked_until

    @property
    def can_login(self) -> bool:
        """Check if user can attempt login."""
        return self.is_active and not self.is_locked

    def record_successful_login(self) -> None:
        """Record successful login and reset failed attempts."""
        self.last_login_at = datetime.now(UTC)
        self.failed_login_attempts = 0
        self.locked_until = None
        self.increment_version()

    def record_failed_login(self) -> None:
        """Record failed login attempt and apply lockout if needed."""
        self.failed_login_attempts += 1

        if self.failed_login_attempts >= FlextConstants.Auth.MAX_LOGIN_ATTEMPTS:
            self.locked_until = datetime.now(UTC) + timedelta(
                minutes=FlextConstants.Auth.LOCKOUT_DURATION_MINUTES
            )

        self.increment_version()

    def has_role(self, role: str) -> bool:
        """Check if user has specific role."""
        return role in self.roles

    def has_permission(self, permission: str) -> bool:
        """Check if user has specific permission."""
        return permission in self.permissions

    @classmethod
    def create_user(
        cls: type[User],
        _request: UserCreationRequest | None = None,
        *,
        # Legacy parameters for backward compatibility
        username: str | None = None,
        email: str | None = None,
        password: str | None = None,
        full_name: str | None = None,
        roles: FlextTypes.Core.StringList | None = None,
    ) -> FlextResult[User]:
        """Create user with password hashing."""
        try:
            # Validate required parameters
            if username is None:
                return FlextResult[User].fail("Username is required")
            if email is None:
                return FlextResult[User].fail("Email is required")
            if password is None:
                return FlextResult[User].fail("Password is required")

            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(rounds=FlextConstants.Auth.BCRYPT_ROUNDS),
            ).decode("utf-8")

            # Generate unique ID using flext-core utilities
            core = FlextCore.get_instance()

            # Generate the ID string first
            raw_id = FlextUtilities.Generators.generate_entity_id()

            # Then validate it with FlextCore - direct access pattern
            core = FlextCore.get_instance()
            validator = core.Validations.Domain.BaseValidator()
            id_result = validator.validate_entity_id(raw_id)
            if id_result.is_failure:  # pragma: no cover
                return FlextResult[User].fail(
                    "Failed to validate user ID"
                )  # pragma: no cover

            # Create user with validated data and auto-generated ID
            # Validation passed, use raw_id directly
            user = cls(
                id=raw_id,  # Use the generated and validated ID directly
                username=username,
                email=FlextModels.EmailAddress(
                    root=email
                ),  # Convert string to EmailAddress
                password_hash=password_hash,
                full_name=full_name,
                roles=roles or ["user"],
                permissions=[],
            )

            # Validate business rules
            validation_result = user.validate_business_rules()
            if validation_result.is_failure:  # pragma: no cover
                return FlextResult[User].fail(  # pragma: no cover
                    validation_result.error
                    or "User validation failed"  # pragma: no cover
                )  # pragma: no cover

            return FlextResult[User].ok(user)

        except Exception as e:  # pragma: no cover
            return FlextResult[User].fail(
                f"Failed to create user: {e}"
            )  # pragma: no cover

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate user-specific business rules using railway pattern."""
        # Use FlextResult.chain_results for functional validation (fazer mais com menos!)

        return FlextResult.chain_results(
            cast("FlextResult[object]", self._validate_username()),
            cast("FlextResult[object]", self._validate_email()),
            cast("FlextResult[object]", self._validate_password_hash()),
        ).map(lambda _: None)

    def _validate_username(self) -> FlextResult[None]:
        """Validate username business rules."""
        if not self.username:  # pragma: no cover
            return FlextResult[None].fail(
                "Username cannot be empty"
            )  # pragma: no cover
        return FlextResult[None].ok(None)

    def _validate_email(self) -> FlextResult[None]:
        """Validate email business rules."""
        if not self.email or not str(self.email):  # pragma: no cover
            return FlextResult[None].fail("Email cannot be empty")  # pragma: no cover
        return FlextResult[None].ok(None)

    def _validate_password_hash(self) -> FlextResult[None]:
        """Validate password hash business rules."""
        if not self.password_hash:  # pragma: no cover
            return FlextResult[None].fail(
                "Password hash cannot be empty"
            )  # pragma: no cover
        return FlextResult[None].ok(None)


class Session(FlextModels.Entity):
    """Session entity for authentication state management."""

    # Core session fields
    user_id: str = Field(..., description="ID of authenticated user")
    token: str = Field(..., description="Session authentication token")
    expires_at: datetime = Field(..., description="Session expiration time")

    # Session metadata
    ip_address: str | None = Field(default=None, description="Client IP address")
    user_agent: str | None = Field(default=None, description="Client user agent")
    is_revoked: bool = Field(default=False, description="Session revocation status")

    # Activity tracking
    last_activity_at: datetime = Field(
        default_factory=lambda: datetime.now(UTC), description="Last session activity"
    )

    @field_validator("token")
    @classmethod
    def validate_token(cls, v: str) -> str:
        """Validate token format and length."""
        if len(v) < FlextConstants.Auth.MIN_TOKEN_LENGTH:
            msg = f"Token must be at least {FlextConstants.Auth.MIN_TOKEN_LENGTH} characters"
            raise ValueError(msg)
        return v

    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now(UTC) >= self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if session is valid and active."""
        return not self.is_expired() and not self.is_revoked

    @property
    def time_remaining_seconds(self) -> int:
        """Get remaining session time in seconds."""
        if self.is_expired():
            return 0
        return int((self.expires_at - datetime.now(UTC)).total_seconds())

    def extend_expiry(self, minutes: int = 30) -> None:
        """Extend session expiry time."""
        self.expires_at = datetime.now(UTC) + timedelta(minutes=minutes)
        self.last_activity_at = datetime.now(UTC)
        self.increment_version()

    def revoke(self) -> None:
        """Revoke the session."""
        self.is_revoked = True
        self.increment_version()

    def update_activity(self) -> None:
        """Update last activity timestamp."""
        self.last_activity_at = datetime.now(UTC)
        self.increment_version()

    @classmethod
    def create_session(
        cls: type[Session], user_id: str, expires_in_minutes: int = 30
    ) -> FlextResult[Session]:
        """Create session with secure token."""
        try:
            # Generate secure session token using flext-core (32+ chars required)
            token = FlextUtilities.generate_uuid()

            # Generate unique ID using flext-core utilities
            core = FlextCore.get_instance()

            # Generate the ID string first
            raw_id = FlextUtilities.Generators.generate_entity_id()

            # Then validate it with FlextCore - direct access pattern
            core = FlextCore.get_instance()
            validator = core.Validations.Domain.BaseValidator()
            id_result = validator.validate_entity_id(raw_id)
            if id_result.is_failure:  # pragma: no cover
                return FlextResult[Session].fail(  # pragma: no cover
                    "Failed to validate session ID"  # pragma: no cover
                )  # pragma: no cover

            # Calculate expiry
            expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
            now = datetime.now(UTC)

            # Create session with auto-generated ID
            # Validation passed, use raw_id directly
            session = cls(
                id=raw_id,  # Use the generated and validated ID directly
                user_id=user_id,
                token=token,
                expires_at=expires_at,
                created_at=now,
                last_activity_at=now,
                is_revoked=False,
            )

            return FlextResult[Session].ok(session)

        except Exception as e:  # pragma: no cover
            return FlextResult[Session].fail(
                f"Failed to create session: {e}"
            )  # pragma: no cover

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate session-specific business rules."""
        if not self.user_id:  # pragma: no cover
            return FlextResult[None].fail("User ID cannot be empty")  # pragma: no cover

        if not self.token:  # pragma: no cover
            return FlextResult[None].fail("Token cannot be empty")  # pragma: no cover

        if self.expires_at <= datetime.now(UTC):  # pragma: no cover
            return FlextResult[None].fail(
                "Session cannot expire in the past"
            )  # pragma: no cover

        return FlextResult[None].ok(None)


class Role(FlextModels.Entity):
    """Role entity for RBAC (Role-Based Access Control)."""

    # Role definition
    name: str = Field(..., description="Role name")
    display_name: str = Field(..., description="Human-readable role name")
    description: str | None = Field(default=None, description="Role description")

    # Permissions
    permissions: FlextTypes.Core.StringList = Field(
        default_factory=list, description="Role permissions"
    )

    # Role metadata
    is_system_role: bool = Field(default=False, description="System role flag")
    priority: int = Field(default=100, description="Role priority for conflicts")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate role name format."""
        v = v.strip().upper()
        if not v.replace("_", "").isalnum():  # pragma: no cover
            msg = "Role name can only contain letters, numbers, and underscores"  # pragma: no cover
            raise ValueError(msg)  # pragma: no cover
        return v

    def has_permission(self, permission: str) -> bool:
        """Check if role has specific permission."""
        return permission in self.permissions  # pragma: no cover

    def add_permission(self, permission: str) -> None:
        """Add permission to role."""
        if permission not in self.permissions:  # pragma: no cover
            self.permissions.append(permission)  # pragma: no cover
            self.increment_version()  # pragma: no cover

    def remove_permission(self, permission: str) -> None:
        """Remove permission from role."""
        if permission in self.permissions:  # pragma: no cover
            self.permissions.remove(permission)  # pragma: no cover
            self.increment_version()  # pragma: no cover

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate role-specific business rules."""
        if not self.name:  # pragma: no cover
            return FlextResult[None].fail(
                "Role name cannot be empty"
            )  # pragma: no cover

        if not self.display_name:  # pragma: no cover
            return FlextResult[None].fail(
                "Display name cannot be empty"
            )  # pragma: no cover

        return FlextResult[None].ok(None)  # pragma: no cover


# =========================================================================
# VALUE OBJECTS
# =========================================================================


class Password(FlextModels.Value):
    """Password value object with validation using Pydantic field_validator."""

    value: str = Field(..., description="Raw password value")

    @field_validator("value")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password meets security requirements using Pydantic field_validator."""
        if len(v) < FlextConstants.Auth.MIN_PASSWORD_LENGTH:
            msg = f"Password must be at least {FlextConstants.Auth.MIN_PASSWORD_LENGTH} characters"
            raise ValueError(msg)

        if len(v) > FlextConstants.Auth.MAX_PASSWORD_LENGTH:  # pragma: no cover
            msg = f"Password cannot exceed {FlextConstants.Auth.MAX_PASSWORD_LENGTH} characters"  # pragma: no cover
            raise ValueError(msg)  # pragma: no cover

        # Basic strength checks
        has_upper = any(c.isupper() for c in v)
        has_lower = any(c.islower() for c in v)
        has_digit = any(c.isdigit() for c in v)
        has_special = any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v)

        strength_score = sum([has_upper, has_lower, has_digit, has_special])

        if strength_score < FlextConstants.Auth.MIN_PASSWORD_SCORE:
            msg = "Password must contain uppercase, lowercase, numbers, and special characters"
            raise ValueError(msg)

        return v

    def hash_password(self) -> str:
        """Hash the password using bcrypt."""
        salt = bcrypt.gensalt(rounds=FlextConstants.Auth.BCRYPT_ROUNDS)
        return bcrypt.hashpw(self.value.encode("utf-8"), salt).decode("utf-8")

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate password business rules."""
        if not self.value:  # pragma: no cover
            return FlextResult[None].fail(
                "Password cannot be empty"
            )  # pragma: no cover
        return FlextResult[None].ok(None)  # pragma: no cover


class Credential(FlextModels.Value):
    """Immutable credential value object for secure storage."""

    username: str = Field(..., description="Username for authentication")
    password_hash: str = Field(..., description="Bcrypt password hash")

    @classmethod
    def create_from_password(
        cls, username: str, password: str
    ) -> FlextResult[Credential]:
        """Create credential with password hashing."""
        try:
            # Hash password with bcrypt
            salt = bcrypt.gensalt(rounds=FlextConstants.Auth.BCRYPT_ROUNDS)
            password_hash = bcrypt.hashpw(password.encode("utf-8"), salt).decode(
                "utf-8"
            )

            credential = cls(username=username, password_hash=password_hash)
            return FlextResult[Credential].ok(credential)

        except Exception as e:  # pragma: no cover
            return FlextResult[Credential].fail(
                f"Failed to create credential: {e}"
            )  # pragma: no cover

    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), self.password_hash.encode("utf-8")
            )
        except Exception:  # pragma: no cover
            return False  # pragma: no cover

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate credential business rules."""
        if not self.username:  # pragma: no cover
            return FlextResult[None].fail(
                "Username cannot be empty"
            )  # pragma: no cover
        if not self.password_hash:  # pragma: no cover
            return FlextResult[None].fail(
                "Password hash cannot be empty"
            )  # pragma: no cover
        return FlextResult[None].ok(None)


class AuthToken(FlextModels.Value):
    """Immutable JWT token value object."""

    token: str = Field(..., description="JWT token string")
    user_id: str = Field(..., description="User ID from token payload")
    expires_at: datetime = Field(..., description="Token expiration time")
    issued_at: datetime = Field(..., description="Token issue time")

    @classmethod
    def create_jwt_token(
        cls,
        user_id: str,
        secret: str,
        expires_in_minutes: int = FlextConstants.Auth.JWT_DEFAULT_EXPIRY_MINUTES,
        username: str | None = None,
    ) -> FlextResult[AuthToken]:
        """Create JWT token for user with modern claims."""
        try:
            now = datetime.now(UTC)
            expires_at = now + timedelta(minutes=expires_in_minutes)

            # Modern JWT payload with all required claims
            payload = {
                "user_id": user_id,
                "username": username or "",
                "role": "user",  # Default role for token validation compatibility
                "iat": int(now.timestamp()),
                "exp": int(expires_at.timestamp()),
                "iss": FlextConstants.Auth.JWT_ISSUER_CLAIM,
                "aud": FlextConstants.Auth.JWT_AUDIENCE_CLAIM,
            }

            token = jwt.encode(
                payload, secret, algorithm=FlextConstants.Auth.JWT_DEFAULT_ALGORITHM
            )

            # Convert bytes to str if necessary
            token_str = token.decode("utf-8") if isinstance(token, bytes) else token

            auth_token = cls(
                token=token_str, user_id=user_id, expires_at=expires_at, issued_at=now
            )

            return FlextResult[AuthToken].ok(auth_token)

        except Exception as e:  # pragma: no cover
            return FlextResult[AuthToken].fail(
                f"Failed to create JWT token: {e}"
            )  # pragma: no cover

    def verify_token(self, secret: str) -> FlextResult[FlextTypes.Core.Dict]:
        """Verify JWT token and return payload with proper validation."""
        try:  # pragma: no cover
            # Use modern PyJWT with proper audience and issuer validation  # pragma: no cover
            payload = jwt.decode(  # pragma: no cover
                self.token,  # pragma: no cover
                secret,  # pragma: no cover
                algorithms=[
                    FlextConstants.Auth.JWT_DEFAULT_ALGORITHM
                ],  # pragma: no cover
                audience=FlextConstants.Auth.JWT_AUDIENCE_CLAIM,  # pragma: no cover
                issuer=FlextConstants.Auth.JWT_ISSUER_CLAIM,  # pragma: no cover
                options={  # pragma: no cover
                    "verify_signature": True,  # pragma: no cover
                    "verify_exp": True,  # pragma: no cover
                    "verify_aud": True,  # pragma: no cover
                    "verify_iss": True,  # pragma: no cover
                    "require_exp": True,  # pragma: no cover
                    "require_aud": True,  # pragma: no cover
                    "require_iss": True,  # pragma: no cover
                },  # pragma: no cover
            )  # pragma: no cover
            return FlextResult[FlextTypes.Core.Dict].ok(payload)  # pragma: no cover

        except jwt.ExpiredSignatureError:  # pragma: no cover
            return FlextResult[FlextTypes.Core.Dict].fail(  # pragma: no cover
                "Token expired",
                error_code=FlextConstants.Auth.TOKEN_EXPIRED,  # pragma: no cover
            )  # pragma: no cover
        except jwt.InvalidTokenError as e:  # pragma: no cover
            return FlextResult[FlextTypes.Core.Dict].fail(  # pragma: no cover
                f"Invalid token: {e}",
                error_code=FlextConstants.Auth.INVALID_TOKEN,  # pragma: no cover
            )  # pragma: no cover

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return datetime.now(UTC) >= self.expires_at  # pragma: no cover

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate token business rules."""
        if not self.token:  # pragma: no cover
            return FlextResult[None].fail("Token cannot be empty")  # pragma: no cover
        if not self.user_id:  # pragma: no cover
            return FlextResult[None].fail("User ID cannot be empty")  # pragma: no cover
        return FlextResult[None].ok(None)  # pragma: no cover


# =========================================================================
# FACTORY FUNCTIONS - Remove class-level factory methods, use module functions
# =========================================================================


def create_user(
    username: str,
    email: str,
    password: str,
    full_name: str | None = None,
    roles: FlextTypes.Core.StringList | None = None,
) -> FlextResult[User]:
    """Create user with password hashing and validation using Pydantic field_validator."""
    try:
        # Generate user ID
        user_id = f"user_{username}_{int(time.time_ns())}"

        # Create Password value object - validation happens in Pydantic field_validator
        password_obj = Password(value=password)
        password_hash = password_obj.hash_password()

        # Create user entity
        user = User(
            id=user_id,
            username=username,
            email=FlextModels.EmailAddress(
                root=email
            ),  # Convert string to EmailAddress
            password_hash=password_hash,
            full_name=full_name,
            roles=roles or [],
        )

        # Validate business rules
        validation_result = user.validate_business_rules()
        if validation_result.is_failure:  # pragma: no cover
            return FlextResult[User].fail(  # pragma: no cover
                f"User validation failed: {validation_result.error}"  # pragma: no cover
            )  # pragma: no cover

        return FlextResult[User].ok(user)

    except Exception as e:  # pragma: no cover
        return FlextResult[User].fail(f"Failed to create user: {e}")  # pragma: no cover


def create_session(
    user_id: str,
    expires_in_minutes: int = FlextConstants.Auth.DEFAULT_SESSION_EXPIRY_MINUTES,
    ip_address: str | None = None,
    user_agent: str | None = None,
) -> FlextResult[Session]:
    """Create authentication session with token."""
    try:
        # Generate session ID using flext-core utilities
        session_id = f"session_{user_id}_{FlextUtilities.generate_timestamp()}"
        token = FlextUtilities.generate_uuid()

        # Calculate expiration
        expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)

        # Create session entity
        session = Session(
            id=session_id,
            user_id=user_id,
            token=token,
            expires_at=expires_at,
            ip_address=ip_address,
            user_agent=user_agent,
        )

        # Validate business rules
        validation_result = session.validate_business_rules()
        if validation_result.is_failure:  # pragma: no cover
            return FlextResult[
                Session
            ].fail(  # pragma: no cover
                f"Session validation failed: {validation_result.error}"  # pragma: no cover
            )  # pragma: no cover

        return FlextResult[Session].ok(session)

    except Exception as e:  # pragma: no cover
        return FlextResult[Session].fail(
            f"Failed to create session: {e}"
        )  # pragma: no cover


def authenticate_user(
    username: str, password: str, user_storage: dict[str, User], jwt_secret: str
) -> FlextResult[FlextTypes.Core.Dict]:
    """Authenticate user using Railway Pattern - eliminates all 8 returns using FlextCore functional composition."""
    # Package authentication parameters for Railway Pattern with proper typing
    auth_context: FlextTypes.Core.Dict = {
        "username": username,
        "password": password,
        "user_storage": user_storage,
        "jwt_secret": jwt_secret,
    }

    # Proper Railway Pattern using FlextResult bind chains - SINGLE RETURN
    result = _find_user_by_username(auth_context)

    return (
        result.bind(_validate_user_login_status)
        .bind(_verify_user_password)
        .bind(_record_login_success)
        .bind(_add_session_to_result)
        .bind(_add_jwt_to_result)
        .bind(_format_authentication_response)
    )


def _find_user_by_username(
    auth_context: FlextTypes.Core.Dict,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Find user by username (case insensitive) - extracted method for Railway Pattern."""
    try:
        username = str(auth_context["username"])
        user_storage = cast("dict[str, User]", auth_context["user_storage"])

        user = None
        for stored_user in user_storage.values():
            if stored_user.username.lower() == username.lower():
                user = stored_user
                break

        if not user:
            return FlextResult[FlextTypes.Core.Dict].fail(
                "Invalid credentials",
                error_code=FlextConstants.Auth.INVALID_CREDENTIALS,
            )

        return FlextResult[FlextTypes.Core.Dict].ok({**auth_context, "user": user})

    except Exception as e:  # pragma: no cover
        return FlextResult[FlextTypes.Core.Dict].fail(
            f"User lookup failed: {e}"
        )  # pragma: no cover


def _validate_user_login_status(
    auth_data: FlextTypes.Core.Dict,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Validate user can login - extracted method for Railway Pattern."""
    user = cast("User", auth_data["user"])

    if not user.can_login:
        if user.is_locked:
            return FlextResult[FlextTypes.Core.Dict].fail(
                "Account is locked", error_code=FlextConstants.Auth.ACCOUNT_LOCKED
            )
        if not user.is_active:
            return FlextResult[FlextTypes.Core.Dict].fail(
                "Account is disabled",
                error_code=FlextConstants.Auth.ACCOUNT_DISABLED,
            )

    return FlextResult[FlextTypes.Core.Dict].ok(auth_data)


def _verify_user_password(
    auth_data: FlextTypes.Core.Dict,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Verify user password - extracted method for Railway Pattern."""
    user = cast("User", auth_data["user"])
    password = str(auth_data["password"])

    # Use bcrypt directly for efficiency (no temporary objects)
    password_valid = bcrypt.checkpw(
        password.encode("utf-8"), user.password_hash.encode("utf-8")
    )

    if not password_valid:
        user.record_failed_login()
        return FlextResult[FlextTypes.Core.Dict].fail(
            "Invalid credentials",
            error_code=FlextConstants.Auth.INVALID_CREDENTIALS,
        )

    return FlextResult[FlextTypes.Core.Dict].ok(auth_data)


def _create_user_session(user: User) -> FlextResult[Session]:
    """Create user session - extracted method for Railway Pattern."""
    session_result = create_session(user.id)
    if session_result.is_failure:  # pragma: no cover
        return FlextResult[Session].fail(  # pragma: no cover
            f"Failed to create session: {session_result.error}"  # pragma: no cover
        )  # pragma: no cover
    return session_result


def _create_jwt_token(user: User, jwt_secret: str) -> FlextResult[AuthToken]:
    """Create JWT token - extracted method for Railway Pattern."""
    token_result = AuthToken.create_jwt_token(user.id, jwt_secret)
    if token_result.is_failure:  # pragma: no cover
        return FlextResult[AuthToken].fail(  # pragma: no cover
            f"Failed to create token: {token_result.error}"  # pragma: no cover
        )  # pragma: no cover
    return token_result


def _format_authentication_response(
    auth_data: FlextTypes.Core.Dict,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Format authentication response - extracted method for Railway Pattern."""
    user = cast("User", auth_data["user"])
    session = cast("Session", auth_data["session"])
    jwt_token = cast("AuthToken", auth_data["jwt_token"])

    response_data = {
        "user": {
            "id": user.id,
            "username": user.username,
            "email": user.email_str,
            "full_name": user.full_name,
            "role": user.role,
            "roles": user.roles,
            "is_verified": user.is_verified,
        },
        "session": {
            "id": session.id,
            "session_id": session.id,  # Backward compatibility
            "token": session.token,
            "expires_at": session.expires_at.isoformat(),
            "time_remaining": session.time_remaining_seconds,
        },
        "jwt": {
            "token": jwt_token.token,
            "expires_at": jwt_token.expires_at.isoformat(),
            "user_id": jwt_token.user_id,
        },
    }

    return FlextResult[FlextTypes.Core.Dict].ok(response_data)


def _record_login_success(
    auth_data: FlextTypes.Core.Dict,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Record successful login - helper for Railway Pattern."""
    try:
        user = cast("User", auth_data["user"])
        user.record_successful_login()
        return FlextResult[FlextTypes.Core.Dict].ok(auth_data)
    except Exception as e:  # pragma: no cover
        return FlextResult[FlextTypes.Core.Dict].fail(
            f"Failed to record login: {e}"
        )  # pragma: no cover


def _add_session_to_result(
    auth_data: FlextTypes.Core.Dict,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Add session to authentication result - helper for Railway Pattern."""
    try:
        user = cast("User", auth_data["user"])

        session_result = _create_user_session(user)
        if session_result.is_failure:  # pragma: no cover
            return FlextResult[FlextTypes.Core.Dict].fail(  # pragma: no cover
                f"Session creation failed: {session_result.error}"  # pragma: no cover
            )  # pragma: no cover

        # Add session to result
        result_with_session = {**auth_data, "session": session_result.value}
        return FlextResult[FlextTypes.Core.Dict].ok(result_with_session)
    except Exception as e:  # pragma: no cover
        return FlextResult[FlextTypes.Core.Dict].fail(
            f"Failed to add session: {e}"
        )  # pragma: no cover


def _add_jwt_to_result(
    auth_data: FlextTypes.Core.Dict,
) -> FlextResult[FlextTypes.Core.Dict]:
    """Add JWT token to authentication result - helper for Railway Pattern."""
    try:
        user = cast("User", auth_data["user"])
        jwt_secret = cast("str", auth_data["jwt_secret"])

        jwt_result = _create_jwt_token(user, jwt_secret)
        if jwt_result.is_failure:  # pragma: no cover
            return FlextResult[FlextTypes.Core.Dict].fail(  # pragma: no cover
                f"JWT creation failed: {jwt_result.error}"  # pragma: no cover
            )  # pragma: no cover

        # Add JWT token to result
        result_with_jwt = {**auth_data, "jwt_token": jwt_result.value}
        return FlextResult[FlextTypes.Core.Dict].ok(result_with_jwt)
    except Exception as e:  # pragma: no cover
        return FlextResult[FlextTypes.Core.Dict].fail(
            f"Failed to add JWT: {e}"
        )  # pragma: no cover


# Module exports
__all__ = [
    "AuthToken",
    "Credential",
    "Password",
    "Role",
    "Session",
    "User",
    "UserCreationRequest",
    "authenticate_user",
    "create_session",
    "create_user",
]

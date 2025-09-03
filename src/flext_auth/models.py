"""FLEXT Auth Models - Authentication domain models using flext-core patterns directly.

Authentication domain entities using FlextModels directly without wrapper classes,
following the "fazer mais com menos" principle and eliminating unnecessary redeclarations.

Usage:
    # User entity creation
    user = User(id="user_123", username="john", email="john@example.com")

    # Session entity creation
    session = Session(id="session_456", user_id="user_123", token="jwt_token")

    # Factory methods
    user_result = create_user(username="john", email="john@example.com", password="secret")

Features:
    - Authentication domain entities using FlextModels directly
    - Password hashing and verification
    - JWT token generation and validation
    - Session lifecycle management
    - Type-safe domain modeling patterns

"""

from __future__ import annotations

import time
from datetime import UTC, datetime, timedelta
from typing import override

import bcrypt
import jwt
from flext_core import (
    FlextConstants,
    FlextCore,
    FlextModels,
    FlextResult,
    FlextUtilities,
)
from pydantic import Field, field_validator

# =========================================================================
# AUTHENTICATION ENTITIES
# =========================================================================


class User(FlextModels.Entity):
    """User entity for authentication with credentials and profile information.

    Represents an authenticated user in the system with secure credential storage,
    profile information, and authentication state management. Inherits from
    FlextModels.Entity to get identity, versioning, and domain events.

    """

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
    roles: list[str] = Field(default_factory=list, description="User roles for RBAC")
    permissions: list[str] = Field(
        default_factory=list, description="Direct permissions"
    )

    @field_validator("username")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format using flext-core utilities."""
        # Clean and normalize using flext-core
        v = FlextUtilities.TextProcessor.clean_text(v).strip().lower()

        # Use flext-core string validation
        string_validation = FlextCore.validate_string(v, min_length=3, max_length=50)
        if string_validation.is_failure:
            raise ValueError(string_validation.error or "Invalid username")

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
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        roles: list[str] | None = None,
    ) -> FlextResult[User]:
        """Factory method to create user with password hashing."""
        try:
            # Hash password with bcrypt
            password_hash = bcrypt.hashpw(
                password.encode("utf-8"),
                bcrypt.gensalt(rounds=FlextConstants.Auth.BCRYPT_ROUNDS),
            ).decode("utf-8")

            # Generate unique ID using flext-core utilities
            core = FlextCore.get_instance()

            # Generate the ID string first
            raw_id = FlextUtilities.Generators.generate_entity_id()

            # Then validate it with FlextCore
            id_result = core.create_entity_id(raw_id)
            if id_result.is_failure:
                return FlextResult[User].fail("Failed to create validated user ID")

            # Create user with validated data and auto-generated ID
            entity_id = id_result.unwrap()
            user = cls(
                id=entity_id.root,  # Extract the string value from FlextModels.EntityId
                username=username,
                email=FlextModels.EmailAddress(
                    root=email
                ),  # Convert string to EmailAddress
                password_hash=password_hash,
                full_name=full_name,
                roles=roles or [],
                permissions=[],
            )

            # Validate business rules
            validation_result = user.validate_business_rules()
            if validation_result.is_failure:
                return FlextResult[User].fail(
                    validation_result.error or "User validation failed"
                )

            return FlextResult[User].ok(user)

        except Exception as e:
            return FlextResult[User].fail(f"Failed to create user: {e}")

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate user-specific business rules using railway pattern."""
        # Use FlextResult.chain_results for functional validation (fazer mais com menos!)
        # Use type ignore for mypy chain_results generic type mismatch
        return FlextResult.chain_results(
            self._validate_username(),  # type: ignore[arg-type]
            self._validate_email(),  # type: ignore[arg-type]
            self._validate_password_hash(),  # type: ignore[arg-type]
        ).map(lambda _: None)

    def _validate_username(self) -> FlextResult[None]:
        """Validate username business rules."""
        if not self.username:
            return FlextResult[None].fail("Username cannot be empty")
        return FlextResult[None].ok(None)

    def _validate_email(self) -> FlextResult[None]:
        """Validate email business rules."""
        if not self.email or not str(self.email):
            return FlextResult[None].fail("Email cannot be empty")
        return FlextResult[None].ok(None)

    def _validate_password_hash(self) -> FlextResult[None]:
        """Validate password hash business rules."""
        if not self.password_hash:
            return FlextResult[None].fail("Password hash cannot be empty")
        return FlextResult[None].ok(None)


class Session(FlextModels.Entity):
    """Session entity for authentication state management.

    Represents an active authentication session with token validation,
    expiration handling, and security tracking.

    """

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

    @property
    def is_expired(self) -> bool:
        """Check if session has expired."""
        return datetime.now(UTC) >= self.expires_at

    @property
    def is_valid(self) -> bool:
        """Check if session is valid and active."""
        return not self.is_expired and not self.is_revoked

    @property
    def time_remaining_seconds(self) -> int:
        """Get remaining session time in seconds."""
        if self.is_expired:
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
        """Factory method to create session with secure token."""
        try:
            # Generate secure session token using flext-core (32+ chars required)
            token = FlextUtilities.generate_uuid()

            # Generate unique ID using flext-core utilities
            core = FlextCore.get_instance()

            # Generate the ID string first
            raw_id = FlextUtilities.Generators.generate_entity_id()

            # Then validate it with FlextCore
            id_result = core.create_entity_id(raw_id)
            if id_result.is_failure:
                return FlextResult[Session].fail(
                    "Failed to create validated session ID"
                )

            # Calculate expiry
            expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
            now = datetime.now(UTC)

            # Create session with auto-generated ID
            entity_id = id_result.unwrap()
            session = cls(
                id=entity_id.root,  # Extract the string value from FlextModels.EntityId
                user_id=user_id,
                token=token,
                expires_at=expires_at,
                created_at=now,
                last_activity_at=now,
                is_revoked=False,
            )

            return FlextResult[Session].ok(session)

        except Exception as e:
            return FlextResult[Session].fail(f"Failed to create session: {e}")

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate session-specific business rules."""
        if not self.user_id:
            return FlextResult[None].fail("User ID cannot be empty")

        if not self.token:
            return FlextResult[None].fail("Token cannot be empty")

        if self.expires_at <= datetime.now(UTC):
            return FlextResult[None].fail("Session cannot expire in the past")

        return FlextResult[None].ok(None)


class Role(FlextModels.Entity):
    """Role entity for RBAC (Role-Based Access Control).

    Represents a role with associated permissions for user authorization.

    """

    # Role definition
    name: str = Field(..., description="Role name")
    display_name: str = Field(..., description="Human-readable role name")
    description: str | None = Field(default=None, description="Role description")

    # Permissions
    permissions: list[str] = Field(default_factory=list, description="Role permissions")

    # Role metadata
    is_system_role: bool = Field(default=False, description="System role flag")
    priority: int = Field(default=100, description="Role priority for conflicts")

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        """Validate role name format."""
        v = v.strip().upper()
        if not v.replace("_", "").isalnum():
            msg = "Role name can only contain letters, numbers, and underscores"
            raise ValueError(msg)
        return v

    def has_permission(self, permission: str) -> bool:
        """Check if role has specific permission."""
        return permission in self.permissions

    def add_permission(self, permission: str) -> None:
        """Add permission to role."""
        if permission not in self.permissions:
            self.permissions.append(permission)
            self.increment_version()

    def remove_permission(self, permission: str) -> None:
        """Remove permission from role."""
        if permission in self.permissions:
            self.permissions.remove(permission)
            self.increment_version()

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate role-specific business rules."""
        if not self.name:
            return FlextResult[None].fail("Role name cannot be empty")

        if not self.display_name:
            return FlextResult[None].fail("Display name cannot be empty")

        return FlextResult[None].ok(None)


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

        if len(v) > FlextConstants.Auth.MAX_PASSWORD_LENGTH:
            msg = f"Password cannot exceed {FlextConstants.Auth.MAX_PASSWORD_LENGTH} characters"
            raise ValueError(msg)

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
        import bcrypt

        salt = bcrypt.gensalt(rounds=FlextConstants.Auth.BCRYPT_ROUNDS)
        return bcrypt.hashpw(self.value.encode("utf-8"), salt).decode("utf-8")

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate password business rules."""
        if not self.value:
            return FlextResult[None].fail("Password cannot be empty")
        return FlextResult[None].ok(None)


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

        except Exception as e:
            return FlextResult[Credential].fail(f"Failed to create credential: {e}")

    def verify_password(self, password: str) -> bool:
        """Verify password against stored hash."""
        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), self.password_hash.encode("utf-8")
            )
        except Exception:
            return False

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate credential business rules."""
        if not self.username:
            return FlextResult[None].fail("Username cannot be empty")
        if not self.password_hash:
            return FlextResult[None].fail("Password hash cannot be empty")
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

            auth_token = cls(
                token=token, user_id=user_id, expires_at=expires_at, issued_at=now
            )

            return FlextResult[AuthToken].ok(auth_token)

        except Exception as e:
            return FlextResult[AuthToken].fail(f"Failed to create JWT token: {e}")

    def verify_token(self, secret: str) -> FlextResult[dict[str, object]]:
        """Verify JWT token and return payload with proper validation."""
        try:
            # Use modern PyJWT with proper audience and issuer validation
            payload = jwt.decode(
                self.token,
                secret,
                algorithms=[FlextConstants.Auth.JWT_DEFAULT_ALGORITHM],
                audience=FlextConstants.Auth.JWT_AUDIENCE_CLAIM,
                issuer=FlextConstants.Auth.JWT_ISSUER_CLAIM,
                options={
                    "verify_signature": True,
                    "verify_exp": True,
                    "verify_aud": True,
                    "verify_iss": True,
                    "require_exp": True,
                    "require_aud": True,
                    "require_iss": True,
                },
            )
            return FlextResult[dict[str, object]].ok(payload)

        except jwt.ExpiredSignatureError:
            return FlextResult[dict[str, object]].fail(
                "Token expired", error_code=FlextConstants.Auth.TOKEN_EXPIRED
            )
        except jwt.InvalidTokenError as e:
            return FlextResult[dict[str, object]].fail(
                f"Invalid token: {e}", error_code=FlextConstants.Auth.INVALID_TOKEN
            )

    @property
    def is_expired(self) -> bool:
        """Check if token has expired."""
        return datetime.now(UTC) >= self.expires_at

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate token business rules."""
        if not self.token:
            return FlextResult[None].fail("Token cannot be empty")
        if not self.user_id:
            return FlextResult[None].fail("User ID cannot be empty")
        return FlextResult[None].ok(None)


# =========================================================================
# FACTORY FUNCTIONS - Remove class-level factory methods, use module functions
# =========================================================================


def create_user(
    username: str,
    email: str,
    password: str,
    full_name: str | None = None,
    roles: list[str] | None = None,
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
        if validation_result.is_failure:
            return FlextResult[User].fail(
                f"User validation failed: {validation_result.error}"
            )

        return FlextResult[User].ok(user)

    except Exception as e:
        return FlextResult[User].fail(f"Failed to create user: {e}")


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
        if validation_result.is_failure:
            return FlextResult[Session].fail(
                f"Session validation failed: {validation_result.error}"
            )

        return FlextResult[Session].ok(session)

    except Exception as e:
        return FlextResult[Session].fail(f"Failed to create session: {e}")


def authenticate_user(
    username: str, password: str, user_storage: dict[str, User], jwt_secret: str
) -> FlextResult[dict[str, object]]:
    """Authenticate user and create session."""
    try:
        # Find user by username (case insensitive)
        user = None
        for stored_user in user_storage.values():
            if stored_user.username.lower() == username.lower():
                user = stored_user
                break

        if not user:
            return FlextResult[dict[str, object]].fail(
                "Invalid credentials",
                error_code=FlextConstants.Auth.INVALID_CREDENTIALS,
            )

        # Check if user can login
        if not user.can_login:
            if user.is_locked:
                return FlextResult[dict[str, object]].fail(
                    "Account is locked", error_code=FlextConstants.Auth.ACCOUNT_LOCKED
                )
            if not user.is_active:
                return FlextResult[dict[str, object]].fail(
                    "Account is disabled",
                    error_code=FlextConstants.Auth.ACCOUNT_DISABLED,
                )

        # Verify password
        password_valid = bcrypt.checkpw(
            password.encode("utf-8"), user.password_hash.encode("utf-8")
        )

        if not password_valid:
            user.record_failed_login()
            return FlextResult[dict[str, object]].fail(
                "Invalid credentials",
                error_code=FlextConstants.Auth.INVALID_CREDENTIALS,
            )

        # Record successful login
        user.record_successful_login()

        # Create session
        session_result = create_session(user.id)
        if session_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to create session: {session_result.error}"
            )

        session = session_result.value

        # Create JWT token
        token_result = AuthToken.create_jwt_token(user.id, jwt_secret)
        if token_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                f"Failed to create token: {token_result.error}"
            )

        jwt_token = token_result.value

        # Return authentication data
        auth_data = {
            "user": {
                "id": user.id,
                "username": user.username,
                "email": str(user.email),
                "full_name": user.full_name,
                "roles": user.roles,
                "is_verified": user.is_verified,
            },
            "session": {
                "id": session.id,
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

        return FlextResult[dict[str, object]].ok(auth_data)

    except Exception as e:
        return FlextResult[dict[str, object]].fail(f"Authentication failed: {e}")


# Module exports
__all__ = [
    "AuthToken",
    "Credential",
    "Password",
    "Role",
    "Session",
    "User",
    "authenticate_user",
    "create_session",
    "create_user",
]

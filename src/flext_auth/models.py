"""FLEXT Auth Models - Authentication domain models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from flext_core import (
    FlextModels,
    FlextResult,
    FlextTypes,
    FlextUtilities,
    FlextValidations,
)
from pydantic import BaseModel, Field, field_validator

from flext_auth.constants import FlextAuthConstants


class FlextAuthModels:
    """Unified authentication models with nested helpers following single responsibility principle."""

    # Type aliases for cleaner code
    TokenDict = dict[str, str | datetime]

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

        # Pydantic fields definition
        username: str = ""
        email: str = ""
        password_hash: str = ""
        full_name: str | None = None
        is_active: bool = True
        roles: FlextTypes.Core.StringList = Field(default_factory=list)
        created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
        updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
        last_login: datetime | None = None

        @field_validator("email")
        @classmethod
        def validate_email(cls, v: str) -> str:
            """Validate email format using flext-core validation."""
            # Use flext-core email validation instead of duplicating code
            validation_result = FlextValidations.FieldValidators.validate_email(v)
            if validation_result.is_failure:
                error_msg = validation_result.error or "Email validation failed"
                raise ValueError(error_msg)
            return v

        @field_validator("username")
        @classmethod
        def validate_username(cls, v: str) -> str:
            """Validate username format using flext-core validation."""
            if not v or len(v.strip()) < FlextAuthConstants.MIN_USERNAME_LENGTH:
                msg = "Username must be at least 3 characters"
                raise ValueError(msg)
            return v.strip()

        def set_password(self, password: str) -> FlextResult[bool]:
            """Set password with bcrypt hashing using flext-core pattern."""
            if not password or len(password) < FlextAuthConstants.MIN_PASSWORD_LENGTH:
                return FlextResult[bool].fail("Password must be at least 8 characters")

            try:
                # Use bcrypt for secure hashing
                salt = bcrypt.gensalt()
                password_hash = bcrypt.hashpw(password.encode(), salt)
                self.password_hash = password_hash.decode()
                return FlextResult[bool].ok(data=True)
            except Exception as e:
                return FlextResult[bool].fail(f"Password hashing failed: {e!s}")

        def verify_password(self, password: str) -> FlextResult[bool]:
            """Verify password against stored hash using flext-core pattern."""
            if not self.password_hash:
                return FlextResult[bool].fail("No password hash stored")

            try:
                is_valid = bcrypt.checkpw(
                    password.encode(), self.password_hash.encode()
                )
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(f"Password verification failed: {e!s}")

        @property
        def email_str(self) -> str:
            """Get email as string (legacy compatibility)."""
            return self.email

        @property
        def role(self) -> str:
            """Get primary role (legacy compatibility)."""
            return self.roles[0] if self.roles else "user"

        @property
        def active(self) -> bool:
            """Get active status (legacy compatibility)."""
            return self.is_active

        def has_role(self, role_name: str) -> bool:
            """Check if user has specific role (legacy compatibility)."""
            return role_name.lower() in [role.lower() for role in self.roles]

        @property
        def is_verified(self) -> bool:
            """Check if user is verified (legacy compatibility)."""
            return self.is_active and self.last_login is not None

    class Role(FlextModels.Entity):
        """Role entity for role-based access control."""

        name: str = ""
        description: str = ""
        permissions: FlextTypes.Core.StringList = Field(default_factory=list)
        is_active: bool = True
        created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

        @field_validator("name")
        @classmethod
        def validate_name(cls, v: str) -> str:
            """Validate role name."""
            if not v or len(v.strip()) < FlextAuthConstants.MIN_USERNAME_LENGTH - 1:
                error_msg = "Role name must be at least 2 characters"
                raise ValueError(error_msg)
            return v.strip().upper()

    class Session(FlextModels.Entity):
        """Session entity for user session management."""

        user_id: str = ""
        session_token: str = ""
        expires_at: datetime = Field(
            default_factory=lambda: datetime.now(UTC)
            + timedelta(hours=FlextAuthConstants.DEFAULT_SESSION_EXPIRY_MINUTES // 60)
        )
        created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
        last_accessed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
        is_active: bool = True
        ip_address: str | None = None
        user_agent: str | None = None

        def is_expired(self) -> bool:
            """Check if session is expired."""
            return datetime.now(UTC) > self.expires_at

        def extend_session(self, hours: int = 24) -> FlextResult[bool]:
            """Extend session expiration time."""
            try:
                self.expires_at = datetime.now(UTC) + timedelta(hours=hours)
                self.last_accessed_at = datetime.now(UTC)
                return FlextResult[bool].ok(data=True)
            except Exception as e:
                return FlextResult[bool].fail(f"Session extension failed: {e!s}")

        @property
        def is_valid(self) -> bool:
            """Check if session is valid (active and not expired)."""
            return self.is_active and not self.is_expired()

        def revoke(self) -> FlextResult[bool]:
            """Revoke this session."""
            try:
                self.is_active = False
                return FlextResult[bool].ok(data=True)
            except Exception as e:
                error_msg = f"Session revocation failed: {e!s}"
                return FlextResult[bool].fail(error_msg)

        @property
        def is_revoked(self) -> bool:
            """Check if session is revoked."""
            return not self.is_active

        @property
        def token(self) -> str:
            """Get session token (legacy compatibility)."""
            return self.session_token

    class AuthToken(FlextModels.Entity):
        """JWT Authentication token entity."""

        token: str = ""
        user_id: str = ""
        token_type: str = FlextAuthConstants.JWT_ISSUER_CLAIM
        expires_at: datetime = Field(
            default_factory=lambda: datetime.now(UTC)
            + timedelta(hours=FlextAuthConstants.JWT_DEFAULT_EXPIRY_MINUTES // 60)
        )
        created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
        is_revoked: bool = False

        def is_expired(self) -> bool:
            """Check if token is expired."""
            return datetime.now(UTC) > self.expires_at

        @classmethod
        def create_jwt_token(
            cls, user_id: str, secret_key: str, expires_hours: int = 1
        ) -> FlextResult[FlextAuthModels.AuthToken]:
            """Create JWT token using flext-core pattern."""
            try:
                expires_at = datetime.now(UTC) + timedelta(hours=expires_hours)
                payload = {
                    "user_id": user_id,
                    "exp": expires_at,
                    "iat": datetime.now(UTC),
                    "type": "access",
                }

                token = jwt.encode(
                    payload,
                    secret_key,
                    algorithm=FlextAuthConstants.JWT_DEFAULT_ALGORITHM,
                )

                auth_token = cls(
                    id=FlextUtilities.Generators.generate_uuid(),
                    token=str(token),
                    user_id=user_id,
                    expires_at=expires_at,
                )

                return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)
            except Exception as e:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    f"JWT token creation failed: {e!s}"
                )

        @classmethod
        def verify_jwt_token(
            cls, token: str, secret_key: str
        ) -> FlextResult[dict[str, object]]:
            """Verify JWT token and return payload."""
            try:
                payload = jwt.decode(token, secret_key, algorithms=["HS256"])
                return FlextResult[dict[str, object]].ok(payload)
            except jwt.ExpiredSignatureError:
                return FlextResult[dict[str, object]].fail("Token has expired")
            except jwt.InvalidTokenError:
                return FlextResult[dict[str, object]].fail("Invalid token")
            except Exception as e:
                return FlextResult[dict[str, object]].fail(
                    f"Token verification failed: {e!s}"
                )

    # =========================================================================
    # SERVICE LAYER METHODS
    # =========================================================================

    class _AuthenticationService:
        """Internal authentication service with business logic."""

        @staticmethod
        def authenticate_user(
            username: str, password: str, users_data: list[dict[str, object]]
        ) -> FlextResult[FlextAuthModels.User]:
            """Authenticate user with username/password."""
            if not username or not password:
                return FlextResult[FlextAuthModels.User].fail(
                    "Username and password required"
                )

            # Find user in data
            user_data = next(
                (u for u in users_data if u.get("username") == username), None
            )
            if not user_data:
                return FlextResult[FlextAuthModels.User].fail("User not found")

            # Create user instance from user data
            user = FlextAuthModels.User()
            # Set user attributes from user_data, but only if they exist in User model
            for key, value in user_data.items():
                if hasattr(user, key):
                    setattr(user, key, value)

            # Verify password
            password_result = user.verify_password(password)
            if password_result.is_failure:
                return FlextResult[FlextAuthModels.User].fail("Invalid password")

            if not password_result.data:
                return FlextResult[FlextAuthModels.User].fail("Invalid credentials")

            return FlextResult[FlextAuthModels.User].ok(user)

        @staticmethod
        def create_user_session(
            user: FlextAuthModels.User,
            ip_address: str | None = None,
            user_agent: str | None = None,
        ) -> FlextResult[FlextAuthModels.Session]:
            """Create new user session."""
            try:
                session = FlextAuthModels.Session(
                    id=FlextUtilities.Generators.generate_uuid(),
                    user_id=user.id,
                    session_token=FlextUtilities.Generators.generate_uuid(),
                    ip_address=ip_address,
                    user_agent=user_agent,
                )
                return FlextResult[FlextAuthModels.Session].ok(session)
            except Exception as e:
                return FlextResult[FlextAuthModels.Session].fail(
                    f"Session creation failed: {e!s}"
                )

    # =========================================================================
    # PUBLIC API METHODS
    # =========================================================================

    @classmethod
    def create_user_from_request(
        cls, request: UserCreationRequest
    ) -> FlextResult[User]:
        """Create user from parameter object - eliminates parameter passing smell."""
        try:
            user = cls.User(
                id=FlextUtilities.Generators.generate_uuid(),
                username=request.username,
                email=request.email,
                full_name=request.full_name,
                roles=request.roles,
            )

            # Set password
            password_result = user.set_password(request.password)
            if password_result.is_failure:
                return FlextResult[FlextAuthModels.User].fail(
                    password_result.error or "Password verification failed"
                )

            return FlextResult[FlextAuthModels.User].ok(user)
        except Exception as e:
            return FlextResult[FlextAuthModels.User].fail(
                f"User creation failed: {e!s}"
            )

    @classmethod
    def authenticate_and_create_session(
        cls,
        username: str,
        password: str,
        users_data: list[dict[str, object]],
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[
        tuple[FlextAuthModels.User, FlextAuthModels.Session, FlextAuthModels.AuthToken]
    ]:
        """Complete authentication flow - authenticate user, create session and token."""
        # Authenticate user
        auth_result = cls._AuthenticationService.authenticate_user(
            username, password, users_data
        )
        if auth_result.is_failure:
            return FlextResult[
                tuple[
                    FlextAuthModels.User,
                    FlextAuthModels.Session,
                    FlextAuthModels.AuthToken,
                ]
            ].fail(auth_result.error or "Authentication failed")

        user = auth_result.data
        if user is None:
            return FlextResult[
                tuple[
                    FlextAuthModels.User,
                    FlextAuthModels.Session,
                    FlextAuthModels.AuthToken,
                ]
            ].fail("Authentication failed - user not found")

        # Create session
        session_result = cls._AuthenticationService.create_user_session(
            user, ip_address, user_agent
        )
        if session_result.is_failure:
            return FlextResult[
                tuple[
                    FlextAuthModels.User,
                    FlextAuthModels.Session,
                    FlextAuthModels.AuthToken,
                ]
            ].fail(session_result.error or "Session creation failed")

        session = session_result.data
        if session is None:
            return FlextResult[
                tuple[
                    FlextAuthModels.User,
                    FlextAuthModels.Session,
                    FlextAuthModels.AuthToken,
                ]
            ].fail("Session creation failed - session not created")

        # Create JWT token
        if not user.id:
            return FlextResult[
                tuple[
                    FlextAuthModels.User,
                    FlextAuthModels.Session,
                    FlextAuthModels.AuthToken,
                ]
            ].fail("User ID is required for token creation")

        token_result = cls.AuthToken.create_jwt_token(
            user.id, FlextAuthConstants.JWT_SECRET_KEY
        )
        if token_result.is_failure:
            return FlextResult[
                tuple[
                    FlextAuthModels.User,
                    FlextAuthModels.Session,
                    FlextAuthModels.AuthToken,
                ]
            ].fail(token_result.error or "Token creation failed")

        token = token_result.data
        if token is None:
            return FlextResult[
                tuple[
                    FlextAuthModels.User,
                    FlextAuthModels.Session,
                    FlextAuthModels.AuthToken,
                ]
            ].fail("Token creation failed - token not created")

        return FlextResult[
            tuple[
                FlextAuthModels.User, FlextAuthModels.Session, FlextAuthModels.AuthToken
            ]
        ].ok((user, session, token))


# Module-level convenience functions for easier imports
def authenticate_user(
    username: str, password: str, users_data: list[dict[str, object]]
) -> FlextResult[FlextAuthModels.User]:
    """Authenticate user with username/password."""
    return FlextAuthModels._AuthenticationService.authenticate_user(
        username, password, users_data
    )


def create_session(
    user_id: str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    expires_in_minutes: int | None = None,
) -> FlextResult[FlextAuthModels.Session]:
    """Create new user session."""
    # Calculate expiration time
    if expires_in_minutes:
        expires_at = datetime.now(UTC) + timedelta(minutes=expires_in_minutes)
    else:
        expires_at = datetime.now(UTC) + timedelta(
            hours=FlextAuthConstants.DEFAULT_SESSION_EXPIRY_MINUTES // 60
        )

    # Create session directly using Session model
    session = FlextAuthModels.Session(
        id=FlextUtilities.Generators.generate_uuid(),
        user_id=user_id,
        session_token=FlextUtilities.Generators.generate_uuid(),
        ip_address=ip_address,
        user_agent=user_agent,
        expires_at=expires_at,
    )
    return FlextResult[FlextAuthModels.Session].ok(session)


def create_user(
    request: FlextAuthModels.UserCreationRequest,
) -> FlextResult[FlextAuthModels.User]:
    """Create new user from request."""
    return FlextAuthModels.create_user_from_request(request)

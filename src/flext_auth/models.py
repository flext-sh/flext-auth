"""FLEXT Auth Models - Authentication domain models with Pydantic v2.

This module contains only Pydantic BaseModel classes and Settings,
following flext-core standardization without wrappers or aliases.
All type definitions are in typings.py, exceptions in exceptions.py.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from pydantic import BaseModel, Field, ValidationError, field_validator
from pydantic_settings import BaseSettings

from flext_auth.constants import FlextAuthConstants
from flext_core import FlextModels, FlextResult, FlextUtilities


class FlextAuthModels:
    """FLEXT Auth Models - Authentication domain Pydantic models unified class.

    Contains all Pydantic BaseModel classes and Settings for the authentication domain,
    extending flext-core models without wrappers or aliases.
    """

    # Parameter Object Pattern for reducing "many parameters" code smell
    class UserCreationRequest(BaseModel):
        """User creation parameter object using Pydantic for cleaner APIs."""

        username: str
        email: str
        password: str
        full_name: str | None = None
        roles: list[str] = Field(default_factory=lambda: ["user"])

        @field_validator("username")
        @classmethod
        def validate_username_not_empty(cls, v: str) -> str:
            """Validate username is not empty."""
            if not v or not v.strip():
                msg = "Username cannot be empty"
                raise ValueError(msg)
            return v

        @field_validator("email")
        @classmethod
        def validate_email_not_empty(cls, v: str) -> str:
            """Validate email is not empty."""
            if not v or not v.strip():
                msg = "Email cannot be empty"
                raise ValueError(msg)
            return v

        @field_validator("password")
        @classmethod
        def validate_password_not_empty(cls, v: str) -> str:
            """Validate password is not empty."""
            if not v or not v.strip():
                msg = "Password cannot be empty"
                raise ValueError(msg)
            return v

    class User(FlextModels.Entity):
        """User domain model extending FlextModels.Entity."""

        username: str = Field(..., description="Unique username")
        email: str = Field(..., description="User email address")
        password_hash: str = Field(default="", description="Hashed password")
        full_name: str | None = Field(None, description="User's full name")
        is_active: bool = Field(True, description="Whether user account is active")
        roles: list[str] = Field(default_factory=list, description="User roles")
        failed_login_attempts: int = Field(0, description="Failed login attempt count")
        locked_until: datetime | None = Field(
            None, description="Account locked until this time"
        )
        last_login: datetime | None = Field(None, description="Last successful login")

        @field_validator("email")
        @classmethod
        def validate_email_format(cls, v: str) -> str:
            """Validate email format."""
            if "@" not in v:
                msg = "Invalid email format"
                raise ValueError(msg)
            return v

        @field_validator("username")
        @classmethod
        def validate_username_length(cls, v: str) -> str:
            """Validate username length."""
            if len(v) < FlextAuthConstants.MIN_USERNAME_LENGTH:
                msg = f"Username must be at least {FlextAuthConstants.MIN_USERNAME_LENGTH} characters"
                raise ValueError(msg)
            if len(v) > FlextAuthConstants.MAX_USERNAME_LENGTH:
                msg = f"Username cannot exceed {FlextAuthConstants.MAX_USERNAME_LENGTH} characters"
                raise ValueError(msg)
            return v

        @field_validator("username")
        @classmethod
        def validate_username_characters(cls, v: str) -> str:
            """Validate username character restrictions."""
            if not v.replace("_", "").replace("-", "").isalnum():
                msg = "Username must contain only alphanumeric characters, underscores, and hyphens"
                raise ValueError(msg)
            return v

        @field_validator("password_hash")
        @classmethod
        def validate_password_hash(cls, v: str) -> str:
            """Validate password hash format."""
            if v and len(v) < FlextAuthConstants.MIN_BCRYPT_HASH_LENGTH:
                msg = "Invalid password hash format"
                raise ValueError(msg)
            return v

        @property
        def can_login(self) -> bool:
            """Check if user can attempt login."""
            return self.is_active and not self.is_locked

        @property
        def is_locked(self) -> bool:
            """Check if account is currently locked."""
            if self.locked_until is None:
                return False
            return datetime.now(UTC) < self.locked_until

        def verify_password(self, password: str) -> FlextResult[bool]:
            """Verify password against stored hash."""
            try:
                is_valid = bcrypt.checkpw(
                    password.encode("utf-8"), self.password_hash.encode("utf-8")
                )
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(f"Password verification failed: {e}")

        def set_password(self, password: str) -> FlextResult[bool]:
            """Set password with validation and hashing."""
            try:
                if len(password) < FlextAuthConstants.MIN_PASSWORD_LENGTH:
                    return FlextResult[bool].fail(
                        f"Password must be at least {FlextAuthConstants.MIN_PASSWORD_LENGTH} characters"
                    )

                # Check for weak passwords
                weak_passwords = ["123", "abc", "password", "12345678", "aaaaaaaa"]
                if password.lower() in weak_passwords:
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

                # Hash password with bcrypt
                salt = bcrypt.gensalt(rounds=FlextAuthConstants.BCRYPT_ROUNDS)
                hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
                self.password_hash = hashed.decode("utf-8")
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(f"Password hashing failed: {e}")

        def record_successful_login(self) -> None:
            """Record successful login and reset failed attempts."""
            self.failed_login_attempts = 0
            self.locked_until = None
            self.last_login = datetime.now(UTC)

        def record_failed_login(self) -> None:
            """Record failed login attempt and apply lockout if needed."""
            self.failed_login_attempts += 1
            if self.failed_login_attempts >= FlextAuthConstants.MAX_LOGIN_ATTEMPTS:
                self.locked_until = datetime.now(UTC) + timedelta(
                    minutes=FlextAuthConstants.LOCKOUT_DURATION_MINUTES
                )

        @classmethod
        def create_user(
            cls, request: FlextAuthModels.UserCreationRequest
        ) -> FlextResult[FlextAuthModels.User]:
            """Create new user from creation request."""
            try:
                user = cls(
                    id=FlextUtilities.Generators.generate_id(),
                    username=request.username,
                    email=request.email,
                    password_hash="",
                    full_name=request.full_name,
                    is_active=True,
                    roles=request.roles or [],
                    failed_login_attempts=0,
                    locked_until=None,
                    last_login=None,
                    created_at=datetime.now(UTC),
                    updated_at=datetime.now(UTC),
                    domain_events=[],
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

    class Role(FlextModels.Entity):
        """Role domain model extending FlextModels.Entity."""

        name: str = Field(..., description="Role name")
        description: str | None = Field(None, description="Role description")
        permissions: list[str] = Field(
            default_factory=list, description="Role permissions"
        )

        @field_validator("name")
        @classmethod
        def validate_role_name(cls, v: str) -> str:
            """Validate role name is not empty."""
            if not v or not v.strip():
                msg = "Role name cannot be empty"
                raise ValueError(msg)
            return v.upper()

    class Session(FlextModels.Entity):
        """Session domain model extending FlextModels.Entity."""

        user_id: str = Field(..., description="User ID for this session")
        session_token: str = Field(..., description="Unique session token")
        expires_at: datetime = Field(..., description="Session expiration time")
        is_active: bool = Field(True, description="Whether session is active")
        ip_address: str | None = Field(None, description="Client IP address")
        user_agent: str | None = Field(None, description="Client user agent")
        last_accessed_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

        @field_validator("session_token")
        @classmethod
        def validate_session_token_length(cls, v: str) -> str:
            """Validate session token length."""
            if len(v) < FlextAuthConstants.MIN_TOKEN_LENGTH:
                msg = "String should have at least 32 characters"
                raise ValueError(msg)
            return v

        def is_expired(self) -> bool:
            """Check if session is expired."""
            return datetime.now(UTC) > self.expires_at

        @property
        def is_valid(self) -> bool:
            """Check if session is valid."""
            return self.is_active and not self.is_expired()

        @property
        def is_revoked(self) -> bool:
            """Check if session has been revoked."""
            return not self.is_active

        def extend_session(self, hours: int = 2) -> FlextResult[bool]:
            """Extend session expiration time."""
            try:
                self.expires_at = datetime.now(UTC) + timedelta(hours=hours)
                self.last_accessed_at = datetime.now(UTC)
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(f"Session extension failed: {e}")

        def revoke(self) -> FlextResult[bool]:
            """Revoke this session."""
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
            """Create new session for user."""
            try:
                import secrets

                session_token = secrets.token_urlsafe(32)
                expires_at = datetime.now(UTC) + timedelta(hours=expiry_hours)

                session = cls(
                    user_id=user_id,
                    session_token=session_token,
                    expires_at=expires_at,
                    is_active=True,
                    ip_address=ip_address,
                    user_agent=user_agent,
                    domain_events=[],
                )

                return FlextResult[FlextAuthModels.Session].ok(session)
            except Exception as e:
                return FlextResult[FlextAuthModels.Session].fail(
                    f"Session creation failed: {e}"
                )

    class AuthToken(FlextModels.Entity):
        """AuthToken domain model for JWT tokens extending FlextModels.Entity."""

        user_id: str = Field(..., description="User ID for this token")
        token: str = Field(..., description="JWT token string")
        expires_at: datetime = Field(..., description="Token expiration time")
        is_revoked: bool = Field(False, description="Whether token is revoked")
        token_type: str = Field(
            FlextAuthConstants.JWT_DEFAULT_TOKEN_TYPE,
            description="Type of token (access, refresh)",
        )

        @property
        def is_expired(self) -> bool:
            """Check if token is expired."""
            return datetime.now(UTC) > self.expires_at

        @property
        def is_valid(self) -> bool:
            """Check if token is valid (not expired and not revoked)."""
            return not self.is_expired and not self.is_revoked

        def revoke(self) -> FlextResult[bool]:
            """Revoke this token."""
            try:
                self.is_revoked = True
                return FlextResult[bool].ok(True)
            except Exception as e:
                return FlextResult[bool].fail(f"Token revocation failed: {e}")

        @classmethod
        def create_jwt_token(
            cls,
            user_id: str,
            expiry_minutes: int = FlextAuthConstants.JWT_DEFAULT_EXPIRY_MINUTES,
            token_type: str = FlextAuthConstants.JWT_DEFAULT_TOKEN_TYPE,
            jwt_secret: str | None = None,
        ) -> FlextResult[FlextAuthModels.AuthToken]:
            """Create new JWT token for user with configurable secret."""
            try:
                expires_at = datetime.now(UTC) + timedelta(minutes=expiry_minutes)

                payload = {
                    "user_id": user_id,
                    "exp": expires_at,
                    "iat": datetime.now(UTC),
                    "iss": FlextAuthConstants.JWT_ISSUER_CLAIM,
                    "aud": FlextAuthConstants.JWT_AUDIENCE_CLAIM,
                    "type": token_type,
                }

                secret_key = jwt_secret or FlextAuthConstants.JWT_SECRET_KEY
                jwt_token_raw: str | bytes = jwt.encode(
                    payload,
                    secret_key,
                    algorithm=FlextAuthConstants.JWT_DEFAULT_ALGORITHM,
                )

                # jwt.encode can return str or bytes depending on PyJWT version
                jwt_token_str = (
                    jwt_token_raw.decode("utf-8")
                    if isinstance(jwt_token_raw, bytes)
                    else str(jwt_token_raw)
                )

                auth_token = cls(
                    user_id=user_id,
                    token=jwt_token_str,
                    expires_at=expires_at,
                    is_revoked=False,
                    token_type=token_type,
                    domain_events=[],
                )

                return FlextResult[FlextAuthModels.AuthToken].ok(auth_token)
            except Exception as e:
                return FlextResult[FlextAuthModels.AuthToken].fail(
                    f"JWT token creation failed: {e}"
                )

        @classmethod
        def verify_jwt_token(cls, token: str) -> FlextResult[dict[str, str]]:
            """Verify and decode JWT token."""
            try:
                payload = jwt.decode(
                    token,
                    FlextAuthConstants.JWT_SECRET_KEY,
                    algorithms=[FlextAuthConstants.JWT_DEFAULT_ALGORITHM],
                )
                return FlextResult[dict[str, str]].ok(payload)
            except jwt.ExpiredSignatureError:
                return FlextResult[dict[str, str]].fail("Token has expired")
            except jwt.InvalidTokenError:
                return FlextResult[dict[str, str]].fail("Invalid token")
            except Exception as e:
                return FlextResult[dict[str, str]].fail(
                    f"Token verification failed: {e}"
                )

    # Pydantic Settings for configuration
    class FlextAuthConfig(BaseSettings):
        """Authentication configuration as Pydantic Settings."""

        _global_instance: FlextAuthModels.FlextAuthConfig | None = None

        # Authentication-specific logging configuration
        enable_audit_logging: bool = Field(
            default=True, description="Enable detailed audit logging"
        )
        log_auth_attempts: bool = Field(
            default=True, description="Log authentication attempts"
        )
        log_auth_failures: bool = Field(
            default=True, description="Log authentication failures"
        )
        log_auth_success: bool = Field(
            default=False, description="Log successful authentications"
        )
        log_token_creation: bool = Field(
            default=True, description="Log token creation events"
        )
        log_token_validation: bool = Field(
            default=False, description="Log token validation events"
        )
        log_user_creation: bool = Field(
            default=True, description="Log user creation events"
        )
        log_user_deletion: bool = Field(
            default=True, description="Log user deletion events"
        )
        log_permission_changes: bool = Field(
            default=True, description="Log permission changes"
        )

        # Security configuration
        max_login_attempts: int = Field(
            default=FlextAuthConstants.MAX_LOGIN_ATTEMPTS,
            description="Maximum failed login attempts before account lockout",
        )
        lockout_duration_minutes: int = Field(
            default=FlextAuthConstants.LOCKOUT_DURATION_MINUTES,
            description="Account lockout duration in minutes",
        )

        # JWT configuration
        jwt_secret_key: str = Field(
            default=FlextAuthConstants.JWT_SECRET_KEY,
            description="JWT secret key",
        )
        jwt_expiry_minutes: int = Field(
            default=FlextAuthConstants.JWT_DEFAULT_EXPIRY_MINUTES,
            description="JWT token expiry in minutes",
        )
        jwt_algorithm: str = Field(
            default=FlextAuthConstants.JWT_DEFAULT_ALGORITHM,
            description="JWT algorithm",
        )

        # Password configuration
        bcrypt_rounds: int = Field(
            default=FlextAuthConstants.BCRYPT_ROUNDS,
            description="Bcrypt rounds for password hashing",
        )
        min_password_length: int = Field(
            default=FlextAuthConstants.MIN_PASSWORD_LENGTH,
            description="Minimum password length",
        )

        # Session configuration
        session_expiry_hours: int = Field(
            default=2,
            description="Session expiry in hours",
        )

        # Security logging configuration
        mask_passwords: bool = Field(
            default=True, description="Mask passwords in log messages"
        )
        mask_tokens: bool = Field(
            default=True, description="Mask tokens in log messages"
        )
        mask_session_ids: bool = Field(
            default=True, description="Mask session IDs in log messages"
        )

        # Performance tracking
        track_auth_performance: bool = Field(
            default=True, description="Track authentication performance"
        )

        class Config:
            """Pydantic configuration for FlextAuthConfig."""

            env_prefix = "AUTH_"
            case_sensitive = False

        def get_auth_logging_config(self) -> dict[str, object]:
            """Get authentication-specific logging configuration dictionary."""
            return {
                "enable_audit_logging": self.enable_audit_logging,
                "log_auth_attempts": self.log_auth_attempts,
                "log_auth_failures": self.log_auth_failures,
                "log_auth_success": self.log_auth_success,
                "log_token_creation": self.log_token_creation,
                "log_token_validation": self.log_token_validation,
                "log_user_creation": self.log_user_creation,
                "log_user_deletion": self.log_user_deletion,
                "log_permission_changes": self.log_permission_changes,
                "mask_passwords": self.mask_passwords,
                "mask_tokens": self.mask_tokens,
                "mask_session_ids": self.mask_session_ids,
                "track_auth_performance": self.track_auth_performance,
            }

        @classmethod
        def create_for_environment(
            cls, environment: str = "development"
        ) -> FlextResult[FlextAuthModels.FlextAuthConfig]:
            """Create configuration for specific environment."""
            try:
                config = cls()
                return FlextResult[FlextAuthModels.FlextAuthConfig].ok(config)
            except Exception as e:
                return FlextResult[FlextAuthModels.FlextAuthConfig].fail(
                    f"Failed to create config for environment {environment}: {e}"
                )

        @classmethod
        def get_global_instance(cls) -> FlextAuthModels.FlextAuthConfig:
            """Get global singleton instance of FlextAuthConfig."""
            if not hasattr(cls, "_global_instance") or cls._global_instance is None:
                cls._global_instance = cls()
            return cls._global_instance

        @classmethod
        def _reset_global_instance(cls) -> None:
            """Reset global instance (for testing)."""
            cls._global_instance = None


__all__ = [
    "FlextAuthModels",
]

"""Value objects for authentication domain."""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime

from flext_core import FlextValueObject
from flext_core.exceptions import FlextValidationError
from pydantic import EmailStr, Field, field_validator

# Constants for validation limits
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MIN_BCRYPT_HASH_LENGTH = 60
MIN_AUTH_TOKEN_LENGTH = 10
MIN_REFRESH_TOKEN_LENGTH = 32
MIN_SESSION_TOKEN_LENGTH = 16
MAX_USER_AGENT_LENGTH = 500
MIN_PASSWORD_RESET_TOKEN_LENGTH = 32
MIN_EMAIL_VERIFICATION_TOKEN_LENGTH = 32


class FlextUsername(FlextValueObject):
    """Username value object with validation."""

    value: str = Field(..., min_length=3, max_length=50)

    @field_validator("value")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            msg = "Username can only contain letters, numbers, underscores, and hyphens"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_USERNAME",
                details={"username": v, "pattern": "^[a-zA-Z0-9_-]+$"},
            )
        return v.lower()

    def __str__(self) -> str:
        """Return username as string."""
        return self.value

    def validate_domain_rules(self) -> None:
        """Validate username domain rules and business constraints."""
        if len(self.value) < MIN_USERNAME_LENGTH:
            msg = "Username must be at least 3 characters"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_USERNAME_LENGTH",
                details={
                    "username": self.value,
                    "min_length": MIN_USERNAME_LENGTH,
                    "actual_length": len(self.value),
                },
            )
        if len(self.value) > MAX_USERNAME_LENGTH:
            msg = "Username must be at most 50 characters"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_USERNAME_LENGTH",
                details={
                    "username": self.value,
                    "max_length": MAX_USERNAME_LENGTH,
                    "actual_length": len(self.value),
                },
            )
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.value):
            msg = "Username can only contain letters, numbers, underscores, and hyphens"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_USERNAME",
                details={"username": self.value, "pattern": "^[a-zA-Z0-9_-]+$"},
            )


class FlextUserEmail(FlextValueObject):
    """Email value object with validation."""

    value: EmailStr

    def __str__(self) -> str:
        """Return email as string."""
        return str(self.value)

    def validate_domain_rules(self) -> None:
        """Validate email domain rules and business constraints."""
        if "@" not in str(self.value):
            msg = "Email must contain @ symbol"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_EMAIL",
                details={"email": str(self.value)},
            )
        # Additional validation is handled by EmailStr type


class FlextPlainPassword(FlextValueObject):
    """Plain password value object with validation."""

    value: str = Field(..., min_length=8, max_length=128)

    @field_validator("value")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if not re.search(r"[A-Z]", v):
            msg = "Password must contain at least one uppercase letter"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_PASSWORD_STRENGTH",
                details={"requirement": "uppercase_letter"},
            )
        if not re.search(r"[a-z]", v):
            msg = "Password must contain at least one lowercase letter"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_PASSWORD_STRENGTH",
                details={"requirement": "lowercase_letter"},
            )
        if not re.search(r"\d", v):
            msg = "Password must contain at least one number"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_PASSWORD_STRENGTH",
                details={"requirement": "number"},
            )
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            msg = "Password must contain at least one special character"
            raise FlextValidationError(
                message=msg,
                error_code="AUTH_INVALID_PASSWORD_STRENGTH",
                details={"requirement": "special_character"},
            )
        return v

    def __str__(self) -> str:
        """Return protected password."""
        return "[PROTECTED]"

    def __repr__(self) -> str:
        """Return protected password representation."""
        return "PlainPassword([PROTECTED])"

    def validate_domain_rules(self) -> None:
        """Validate plain password domain rules and business constraints."""
        if len(self.value) < MIN_PASSWORD_LENGTH:
            msg = "Password must be at least 8 characters"
            raise ValueError(msg)
        if len(self.value) > MAX_PASSWORD_LENGTH:
            msg = "Password must be at most 128 characters"
            raise ValueError(msg)
        if not re.search(r"[A-Z]", self.value):
            msg = "Password must contain at least one uppercase letter"
            raise ValueError(msg)
        if not re.search(r"[a-z]", self.value):
            msg = "Password must contain at least one lowercase letter"
            raise ValueError(msg)
        if not re.search(r"\d", self.value):
            msg = "Password must contain at least one number"
            raise ValueError(msg)
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', self.value):
            msg = "Password must contain at least one special character"
            raise ValueError(msg)


class FlextHashedPassword(FlextValueObject):
    """Hashed password value object."""

    value: str = Field(..., min_length=60)  # bcrypt hashes are typically 60 chars

    @field_validator("value")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        """Validate bcrypt hash format."""
        if not v.startswith("$2b$"):
            msg = "Invalid bcrypt hash format"
            raise ValueError(msg)
        return v

    def __str__(self) -> str:
        """Return hashed password."""
        return "[HASHED]"

    def __repr__(self) -> str:
        """Return hashed password representation."""
        return "HashedPassword([HASHED])"

    def validate_domain_rules(self) -> None:
        """Validate hashed password domain rules and business constraints."""
        if len(self.value) < MIN_BCRYPT_HASH_LENGTH:
            msg = "Invalid bcrypt hash length"
            raise ValueError(msg)
        if not self.value.startswith("$2b$"):
            msg = "Invalid bcrypt hash format"
            raise ValueError(msg)


class FlextAuthToken(FlextValueObject):
    """Authentication token value object."""

    value: str = Field(..., min_length=1)
    token_type: str = Field(default="Bearer")

    def __str__(self) -> str:
        """Return auth token."""
        return f"{self.token_type} {self.value}"

    def validate_domain_rules(self) -> None:
        """Validate auth token domain rules and business constraints."""
        if not self.value:
            msg = "Auth token value cannot be empty"
            raise ValueError(msg)
        if not self.token_type:
            msg = "Token type cannot be empty"
            raise ValueError(msg)
        if len(self.value) < MIN_AUTH_TOKEN_LENGTH:
            msg = "Auth token must be at least 10 characters"
            raise ValueError(msg)


class FlextRefreshToken(FlextValueObject):
    """Refresh token value object."""

    value: str = Field(..., min_length=1)

    def __str__(self) -> str:
        """Return refresh token."""
        return "[REFRESH_TOKEN]"

    def __repr__(self) -> str:
        """Return refresh token representation."""
        return "RefreshToken([PROTECTED])"

    def validate_domain_rules(self) -> None:
        """Validate refresh token domain rules and business constraints."""
        if not self.value:
            msg = "Refresh token value cannot be empty"
            raise ValueError(msg)
        if len(self.value) < MIN_REFRESH_TOKEN_LENGTH:
            msg = "Refresh token must be at least 32 characters"
            raise ValueError(msg)


class FlextSessionToken(FlextValueObject):
    """Session token value object."""

    value: str = Field(..., min_length=1)

    def __str__(self) -> str:
        """Return session token."""
        return "[SESSION_TOKEN]"

    def __repr__(self) -> str:
        """Return session token representation."""
        return "SessionToken([PROTECTED])"

    def validate_domain_rules(self) -> None:
        """Validate session token domain rules and business constraints."""
        if not self.value:
            msg = "Session token value cannot be empty"
            raise ValueError(msg)
        if len(self.value) < MIN_SESSION_TOKEN_LENGTH:
            msg = "Session token must be at least 16 characters"
            raise ValueError(msg)


class FlextIPAddress(FlextValueObject):
    """IP address value object with validation."""

    value: str = Field(..., min_length=7, max_length=45)  # IPv4 or IPv6

    @field_validator("value")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            msg = f"Invalid IP address: {e}"
            raise ValueError(msg) from e
        else:
            return v

    def __str__(self) -> str:
        """Return user agent."""
        return self.value

    def validate_domain_rules(self) -> None:
        """Validate IP address domain rules and business constraints."""
        try:
            ipaddress.ip_address(self.value)
        except ValueError as e:
            msg = f"Invalid IP address: {e}"
            raise ValueError(msg) from e


class FlextUserAgent(FlextValueObject):
    """User agent value object."""

    value: str = Field(..., max_length=500)

    def __str__(self) -> str:
        """Return user agent."""
        return self.value

    def is_mobile(self) -> bool:
        """Check if user agent indicates mobile device."""
        mobile_indicators = ["Mobile", "Android", "iPhone", "iPad", "Windows Phone"]
        return any(indicator in self.value for indicator in mobile_indicators)

    def get_browser(self) -> str:
        """Extract browser name from user agent."""
        if "Chrome" in self.value:
            return "Chrome"
        if "Firefox" in self.value:
            return "Firefox"
        if "Safari" in self.value:
            return "Safari"
        if "Edge" in self.value:
            return "Edge"
        return "Unknown"

    def validate_domain_rules(self) -> None:
        """Validate user agent domain rules and business constraints."""
        if not self.value:
            msg = "User agent cannot be empty"
            raise ValueError(msg)
        if len(self.value) > MAX_USER_AGENT_LENGTH:
            msg = "User agent must be at most 500 characters"
            raise ValueError(msg)


class FlextPasswordResetToken(FlextValueObject):
    """Password reset token value object."""

    value: str = Field(..., min_length=32)

    def __str__(self) -> str:
        """Return password reset token."""
        return "[RESET_TOKEN]"

    def __repr__(self) -> str:
        """Return password reset token representation."""
        return "PasswordResetToken([PROTECTED])"

    def validate_domain_rules(self) -> None:
        """Validate password reset token domain rules and business constraints."""
        if not self.value:
            msg = "Password reset token cannot be empty"
            raise ValueError(msg)
        if len(self.value) < MIN_PASSWORD_RESET_TOKEN_LENGTH:
            msg = "Password reset token must be at least 32 characters"
            raise ValueError(msg)


class FlextEmailVerificationToken(FlextValueObject):
    """Email verification token value object."""

    value: str = Field(..., min_length=32)

    def __str__(self) -> str:
        """Return email verification token."""
        return "[VERIFICATION_TOKEN]"

    def __repr__(self) -> str:
        """Return email verification token representation."""
        return "EmailVerificationToken([PROTECTED])"

    def validate_domain_rules(self) -> None:
        """Validate email verification token domain rules and business constraints."""
        if not self.value:
            msg = "Email verification token cannot be empty"
            raise ValueError(msg)
        if len(self.value) < MIN_EMAIL_VERIFICATION_TOKEN_LENGTH:
            msg = "Email verification token must be at least 32 characters"
            raise ValueError(msg)


class FlextJWTClaims(FlextValueObject):
    """JWT claims value object."""

    sub: str = Field(..., description="Subject (user ID)")
    username: str | None = Field(default=None, description="Username")
    role: str | None = Field(default=None, description="User role")
    iat: int = Field(..., description="Issued at timestamp")
    exp: int = Field(..., description="Expiration timestamp")
    token_type: str = Field(default="access", description="Token type")
    session_id: str | None = Field(default=None, description="Session ID")

    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now(UTC).timestamp() >= self.exp

    def time_until_expiry(self) -> int:
        """Get seconds until token expires."""
        return max(0, int(self.exp - datetime.now(UTC).timestamp()))

    def validate_domain_rules(self) -> None:
        """Validate JWT claims domain rules and business constraints."""
        if not self.sub:
            msg = "JWT subject (sub) cannot be empty"
            raise ValueError(msg)
        if self.iat <= 0:
            msg = "JWT issued at (iat) must be positive"
            raise ValueError(msg)
        if self.exp <= 0:
            msg = "JWT expiration (exp) must be positive"
            raise ValueError(msg)
        if self.exp <= self.iat:
            msg = "JWT expiration must be after issued time"
            raise ValueError(msg)
        if self.token_type not in {"access", "refresh"}:
            msg = "JWT token type must be 'access' or 'refresh'"
            raise ValueError(msg)


class FlextSecurityContext(FlextValueObject):
    """Security context for current request."""

    user_id: str
    username: str
    role: str
    session_id: str
    permissions: list[str] = Field(default_factory=list)
    ip_address: str | None = None
    user_agent: str | None = None

    def has_permission(self, permission: str) -> bool:
        """Check if context has specific permission."""
        return permission in self.permissions

    def is_REDACTED_LDAP_BIND_PASSWORD(self) -> bool:
        """Check if user is REDACTED_LDAP_BIND_PASSWORD."""
        return self.role == "REDACTED_LDAP_BIND_PASSWORD"

    def validate_domain_rules(self) -> None:
        """Validate security context domain rules and business constraints."""
        if not self.user_id:
            msg = "User ID cannot be empty"
            raise ValueError(msg)
        if not self.username:
            msg = "Username cannot be empty"
            raise ValueError(msg)
        if not self.role:
            msg = "Role cannot be empty"
            raise ValueError(msg)
        if not self.session_id:
            msg = "Session ID cannot be empty"
            raise ValueError(msg)
        if self.role not in {"user", "REDACTED_LDAP_BIND_PASSWORD", "moderator"}:
            msg = "Role must be one of: user, REDACTED_LDAP_BIND_PASSWORD, moderator"
            raise ValueError(msg)

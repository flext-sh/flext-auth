"""Value objects for authentication domain."""

from __future__ import annotations

import re
from datetime import UTC

from pydantic import BaseModel, EmailStr, Field, field_validator


class Username(BaseModel):
    """Username value object with validation."""

    value: str = Field(..., min_length=3, max_length=50)

    @field_validator("value")
    @classmethod
    def validate_username(cls, v: str) -> str:
        """Validate username format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            raise ValueError(
                "Username can only contain letters, numbers, underscores, and hyphens"
            )
        return v.lower()

    def __str__(self) -> str:
        return self.value


class UserEmail(BaseModel):
    """Email value object with validation."""

    value: EmailStr

    def __str__(self) -> str:
        return str(self.value)


class PlainPassword(BaseModel):
    """Plain password value object with validation."""

    value: str = Field(..., min_length=8, max_length=128)

    @field_validator("value")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if not re.search(r"[A-Z]", v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", v):
            raise ValueError("Password must contain at least one lowercase letter")
        if not re.search(r"\d", v):
            raise ValueError("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            raise ValueError("Password must contain at least one special character")
        return v

    def __str__(self) -> str:
        return "[PROTECTED]"

    def __repr__(self) -> str:
        return "PlainPassword([PROTECTED])"


class HashedPassword(BaseModel):
    """Hashed password value object."""

    value: str = Field(..., min_length=60)  # bcrypt hashes are typically 60 chars

    @field_validator("value")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        """Validate bcrypt hash format."""
        if not v.startswith("$2b$"):
            raise ValueError("Invalid bcrypt hash format")
        return v

    def __str__(self) -> str:
        return "[HASHED]"

    def __repr__(self) -> str:
        return "HashedPassword([HASHED])"


class AuthToken(BaseModel):
    """Authentication token value object."""

    value: str = Field(..., min_length=1)
    token_type: str = Field(default="Bearer")

    def __str__(self) -> str:
        return f"{self.token_type} {self.value}"


class RefreshToken(BaseModel):
    """Refresh token value object."""

    value: str = Field(..., min_length=1)

    def __str__(self) -> str:
        return "[REFRESH_TOKEN]"

    def __repr__(self) -> str:
        return "RefreshToken([PROTECTED])"


class SessionToken(BaseModel):
    """Session token value object."""

    value: str = Field(..., min_length=1)

    def __str__(self) -> str:
        return "[SESSION_TOKEN]"

    def __repr__(self) -> str:
        return "SessionToken([PROTECTED])"


class IPAddress(BaseModel):
    """IP address value object with validation."""

    value: str = Field(..., min_length=7, max_length=45)  # IPv4 or IPv6

    @field_validator("value")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        import ipaddress

        try:
            ipaddress.ip_address(v)
            return v
        except ValueError as e:
            raise ValueError(f"Invalid IP address: {e}") from e

    def __str__(self) -> str:
        return self.value


class UserAgent(BaseModel):
    """User agent value object."""

    value: str = Field(..., max_length=500)

    def __str__(self) -> str:
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


class PasswordResetToken(BaseModel):
    """Password reset token value object."""

    value: str = Field(..., min_length=32)

    def __str__(self) -> str:
        return "[RESET_TOKEN]"

    def __repr__(self) -> str:
        return "PasswordResetToken([PROTECTED])"


class EmailVerificationToken(BaseModel):
    """Email verification token value object."""

    value: str = Field(..., min_length=32)

    def __str__(self) -> str:
        return "[VERIFICATION_TOKEN]"

    def __repr__(self) -> str:
        return "EmailVerificationToken([PROTECTED])"


class JWTClaims(BaseModel):
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
        from datetime import datetime

        return datetime.now(UTC).timestamp() >= self.exp

    def time_until_expiry(self) -> int:
        """Get seconds until token expires."""
        from datetime import datetime

        return max(0, int(self.exp - datetime.now(UTC).timestamp()))


class SecurityContext(BaseModel):
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

"""FLEXT Auth domain value objects.

Built on flext-core foundation for type-safe authentication values.
Uses modern Python 3.13 patterns and comprehensive validation.
"""

from __future__ import annotations

import re
import secrets
from datetime import datetime
from datetime import timedelta
from enum import StrEnum
from typing import Any

from pydantic import Field
from pydantic import field_validator

from flext_core import DomainValueObject


class UserEmail(DomainValueObject):
    """Email address value object with comprehensive validation."""

    value: str = Field(..., min_length=1, max_length=255, description="Email address")

    @field_validator("value")
    @classmethod
    def validate_email_format(cls, v: str) -> str:
        """Validate email format using RFC-compliant pattern."""
        pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
        if not re.match(pattern, v):
            msg = "Invalid email format"
            raise ValueError(msg)
        return v.lower()

    @property
    def domain(self) -> str:
        """Get the domain part of the email."""
        return self.value.split("@")[1]

    @property
    def local_part(self) -> str:
        """Get the local part of the email."""
        return self.value.split("@")[0]

    @property
    def is_corporate_domain(self) -> bool:
        """Check if email is from a corporate domain."""
        corporate_domains = {"gmail.com", "yahoo.com", "hotmail.com", "outlook.com"}
        return self.domain not in corporate_domains


class Username(DomainValueObject):
    """Username value object with validation rules."""

    value: str = Field(..., min_length=3, max_length=50, description="Username")

    @field_validator("value")
    @classmethod
    def validate_username_format(cls, v: str) -> str:
        """Validate username format and characters."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            msg = "Username can only contain letters, numbers, underscores, and hyphens"
            raise ValueError(msg)

        if v.startswith(("-", "_")) or v.endswith(("-", "_")):
            msg = "Username cannot start or end with special characters"
            raise ValueError(msg)

        return v.lower()

    @property
    def is_valid_length(self) -> bool:
        """Check if username has valid length."""
        return 3 <= len(self.value) <= 50


class HashedPassword(DomainValueObject):
    """Hashed password value object."""

    value: str = Field(..., min_length=1, description="Bcrypt hashed password")

    @field_validator("value")
    @classmethod
    def validate_hash_format(cls, v: str) -> str:
        """Validate bcrypt hash format."""
        if not v.startswith("$2"):
            msg = "Invalid password hash format"
            raise ValueError(msg)
        return v

    @property
    def algorithm(self) -> str:
        """Get the hashing algorithm identifier."""
        return self.value.split("$")[1] if "$" in self.value else "unknown"


class PlainPassword(DomainValueObject):
    """Plain text password for validation before hashing."""

    value: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Plain text password",
    )

    @field_validator("value")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        """Validate password strength requirements."""
        if len(v) < 8:
            msg = "Password must be at least 8 characters long"
            raise ValueError(msg)

        if not re.search(r"[A-Z]", v):
            msg = "Password must contain at least one uppercase letter"
            raise ValueError(msg)

        if not re.search(r"[a-z]", v):
            msg = "Password must contain at least one lowercase letter"
            raise ValueError(msg)

        if not re.search(r"\d", v):
            msg = "Password must contain at least one number"
            raise ValueError(msg)

        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            msg = "Password must contain at least one special character"
            raise ValueError(msg)

        return v

    @property
    def strength_score(self) -> int:
        """Calculate password strength score (0-100)."""
        score = 0

        # Length bonus
        score += min(len(self.value) * 2, 25)

        # Character variety bonus
        if re.search(r"[A-Z]", self.value):
            score += 10
        if re.search(r"[a-z]", self.value):
            score += 10
        if re.search(r"\d", self.value):
            score += 10
        if re.search(r"[!@#$%^&*(),.?\":{}|<>]", self.value):
            score += 15

        # Complexity bonus
        unique_chars = len(set(self.value))
        score += min(unique_chars * 2, 30)

        return min(score, 100)


class SessionToken(DomainValueObject):
    """Session token value object."""

    value: str = Field(..., min_length=32, description="Session token")

    @field_validator("value")
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        """Validate token format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            msg = "Invalid token format"
            raise ValueError(msg)
        return v

    @classmethod
    def generate(cls) -> SessionToken:
        """Generate a new secure session token."""
        token = secrets.token_urlsafe(32)
        return cls(value=token)


class AuthToken(DomainValueObject):
    """Authentication token value object."""

    value: str = Field(..., min_length=10, description="Authentication token")
    token_type: str = Field(..., description="Token type (access, refresh, etc.)")

    @field_validator("value")
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        """Validate token format."""
        if not re.match(r"^[a-zA-Z0-9._-]+$", v):
            msg = "Invalid token format"
            raise ValueError(msg)
        return v

    @field_validator("token_type")
    @classmethod
    def validate_token_type(cls, v: str) -> str:
        """Validate token type."""
        allowed_types = {"access", "refresh", "api", "session"}
        if v not in allowed_types:
            msg = f"Token type must be one of: {allowed_types}"
            raise ValueError(msg)
        return v

    @property
    def is_secure_length(self) -> bool:
        """Check if token has secure length."""
        return len(self.value) >= 32


class RefreshToken(DomainValueObject):
    """Refresh token value object."""

    value: str = Field(..., min_length=32, description="Refresh token")

    @field_validator("value")
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        """Validate refresh token format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            msg = "Invalid refresh token format"
            raise ValueError(msg)
        return v

    @classmethod
    def generate(cls) -> RefreshToken:
        """Generate a new secure refresh token."""
        token = secrets.token_urlsafe(48)
        return cls(value=token)


class EmailVerificationToken(DomainValueObject):
    """Email verification token value object."""

    value: str = Field(..., min_length=32, description="Email verification token")
    expires_at: datetime = Field(..., description="Token expiration time")

    @field_validator("value")
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        """Validate verification token format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            msg = "Invalid verification token format"
            raise ValueError(msg)
        return v

    @classmethod
    def generate(cls, expires_in_hours: int = 24) -> EmailVerificationToken:
        """Generate a new email verification token."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=expires_in_hours)
        return cls(value=token, expires_at=expires_at)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now() > self.expires_at

    @property
    def time_until_expiry(self) -> timedelta:
        """Get time remaining until expiry."""
        return self.expires_at - datetime.now()


class PasswordResetToken(DomainValueObject):
    """Password reset token value object."""

    value: str = Field(..., min_length=32, description="Password reset token")
    expires_at: datetime = Field(..., description="Token expiration time")

    @field_validator("value")
    @classmethod
    def validate_token_format(cls, v: str) -> str:
        """Validate reset token format."""
        if not re.match(r"^[a-zA-Z0-9_-]+$", v):
            msg = "Invalid reset token format"
            raise ValueError(msg)
        return v

    @classmethod
    def generate(cls, expires_in_hours: int = 1) -> PasswordResetToken:
        """Generate a new password reset token."""
        token = secrets.token_urlsafe(32)
        expires_at = datetime.now() + timedelta(hours=expires_in_hours)
        return cls(value=token, expires_at=expires_at)

    @property
    def is_expired(self) -> bool:
        """Check if token is expired."""
        return datetime.now() > self.expires_at


class UserRole(StrEnum):
    """User role enumeration."""

    ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
    USER = "user"
    MODERATOR = "moderator"
    GUEST = "guest"


class UserStatus(StrEnum):
    """User status enumeration."""

    ACTIVE = "active"
    INACTIVE = "inactive"
    SUSPENDED = "suspended"
    PENDING_VERIFICATION = "pending_verification"


class SessionStatus(StrEnum):
    """Session status enumeration."""

    ACTIVE = "active"
    EXPIRED = "expired"
    REVOKED = "revoked"
    INVALID = "invalid"


class AuthenticationMethod(StrEnum):
    """Authentication method enumeration."""

    PASSWORD = "password"
    TWO_FACTOR = "two_factor"
    OAUTH = "oauth"
    API_KEY = "api_key"


class IPAddress(DomainValueObject):
    """IP address value object."""

    value: str = Field(..., description="IP address")

    @field_validator("value")
    @classmethod
    def validate_ip_format(cls, v: str) -> str:
        """Validate IP address format."""
        import ipaddress

        try:
            ipaddress.ip_address(v)
            return v
        except ValueError as e:
            msg = "Invalid IP address format"
            raise ValueError(msg) from e

    @property
    def is_private(self) -> bool:
        """Check if IP address is private."""
        import ipaddress

        return ipaddress.ip_address(self.value).is_private

    @property
    def is_loopback(self) -> bool:
        """Check if IP address is loopback."""
        import ipaddress

        return ipaddress.ip_address(self.value).is_loopback


class UserAgent(DomainValueObject):
    """User agent value object."""

    value: str = Field(..., max_length=512, description="User agent string")

    @property
    def browser_info(self) -> dict[str, Any]:
        """Extract basic browser information."""
        value = self.value.lower()

        browser = "unknown"
        if "chrome" in value:
            browser = "chrome"
        elif "firefox" in value:
            browser = "firefox"
        elif "safari" in value:
            browser = "safari"
        elif "edge" in value:
            browser = "edge"

        platform = "unknown"
        if "windows" in value:
            platform = "windows"
        elif "mac" in value:
            platform = "macos"
        elif "linux" in value:
            platform = "linux"
        elif "android" in value:
            platform = "android"
        elif "ios" in value:
            platform = "ios"

        return {
            "browser": browser,
            "platform": platform,
            "is_mobile": any(
                mobile in value for mobile in ["mobile", "android", "iphone"]
            ),
        }

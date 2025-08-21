"""FLEXT Auth Value Objects - Immutable domain values with validation.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import ipaddress
import re
from datetime import UTC, datetime
from typing import override

from flext_core import FlextResult, FlextValidationError, FlextValue
from pydantic import EmailStr, Field, field_validator

# Constants for validation limits
MIN_USERNAME_LENGTH = 3
MAX_USERNAME_LENGTH = 50
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128
MIN_BCRYPT_HASH_LENGTH = 56  # Minimum bcrypt hash length for production
MIN_AUTH_TOKEN_LENGTH = 10
MIN_REFRESH_TOKEN_LENGTH = 32
MIN_SESSION_TOKEN_LENGTH = 16
MAX_USER_AGENT_LENGTH = 500
MIN_PASSWORD_RESET_TOKEN_LENGTH = 32
MIN_EMAIL_VERIFICATION_TOKEN_LENGTH = 32


class FlextUsername(FlextValue):
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
                context={
                    "error_code": "AUTH_INVALID_USERNAME",
                    "username": v,
                    "pattern": "^[a-zA-Z0-9_-]+$",
                },
            )
        return v.lower()

    @override
    def __str__(self) -> str:
        """Return username as string."""
        return self.value

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate username domain rules and business constraints."""
        if len(self.value) < MIN_USERNAME_LENGTH:
            msg = "Username must be at least 3 characters"
            return FlextResult[None].fail(msg)
        if len(self.value) > MAX_USERNAME_LENGTH:
            msg = "Username must be at most 50 characters"
            return FlextResult[None].fail(msg)
        if not re.match(r"^[a-zA-Z0-9_-]+$", self.value):
            msg = "Username can only contain letters, numbers, underscores, and hyphens"
            return FlextResult[None].fail(msg)
        return FlextResult[None].ok(None)


class FlextUserEmail(FlextValue):
    """Email value object with validation."""

    value: EmailStr

    @override
    def __str__(self) -> str:
        """Return email as string."""
        return str(self.value)

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate email domain rules and business constraints."""
        if "@" not in str(self.value):
            msg = "Email must contain @ symbol"
            return FlextResult[None].fail(msg)
        # Additional validation is handled by EmailStr type
        return FlextResult[None].ok(None)


class FlextPlainPassword(FlextValue):
    """Plain password value object with validation."""

    value: str = Field(..., min_length=8, max_length=128)

    @field_validator("value")
    @classmethod
    def validate_password(cls, v: str) -> str:
        """Validate password strength."""
        if not re.search(r"[A-Z]", v):
            msg = "Password must contain at least one uppercase letter"
            raise FlextValidationError(msg, field="value")
        if not re.search(r"[a-z]", v):
            msg = "Password must contain at least one lowercase letter"
            raise FlextValidationError(msg, field="value")
        if not re.search(r"\d", v):
            msg = "Password must contain at least one number"
            raise FlextValidationError(msg, field="value")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', v):
            msg = "Password must contain at least one special character"
            raise FlextValidationError(msg, field="value")
        return v

    @override
    def __str__(self) -> str:
        """Return protected password."""
        return "[PROTECTED]"

    @override
    def __repr__(self) -> str:
        """Return protected password representation."""
        return "FlextPlainPassword([PROTECTED])"

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate plain password domain rules using Railway-Oriented Programming.

        SOLID REFACTORING: Reduced from 7 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        try:
            # REFACTORING: Strategy Pattern - validation rules as strategies
            validation_errors = self._execute_password_validation_strategies()
            if validation_errors:
                return FlextResult[None].fail(
                    validation_errors[0]
                )  # Return first error

            return FlextResult[None].ok(None)

        except Exception as e:
            return FlextResult[None].fail(f"Password validation error: {e}")

    def _execute_password_validation_strategies(self) -> list[str]:
        """Execute all password validation strategies - Railway-Oriented Programming.

        SOLID REFACTORING: Strategy Pattern implementation for password validation.
        """
        errors: list[str] = []

        # Length validation strategies
        if len(self.value) < MIN_PASSWORD_LENGTH:
            errors.append("Password must be at least 8 characters")
        if len(self.value) > MAX_PASSWORD_LENGTH:
            errors.append("Password must be at most 128 characters")

        # Character requirement strategies
        if not re.search(r"[A-Z]", self.value):
            errors.append("Password must contain at least one uppercase letter")
        if not re.search(r"[a-z]", self.value):
            errors.append("Password must contain at least one lowercase letter")
        if not re.search(r"\d", self.value):
            errors.append("Password must contain at least one number")
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', self.value):
            errors.append("Password must contain at least one special character")

        return errors


class FlextHashedPassword(FlextValue):
    """Hashed password value object."""

    value: str = Field(..., min_length=1)  # Allow validation in validate_business_rules

    @field_validator("value")
    @classmethod
    def validate_hash(cls, v: str) -> str:
        """Perform basic validation; detailed checks in validate_business_rules."""
        return v

    @override
    def __str__(self) -> str:
        """Return hashed password."""
        return "[HASHED]"

    @override
    def __repr__(self) -> str:
        """Return hashed password representation."""
        return "FlextHashedPassword([HASHED])"

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate hashed password domain rules and business constraints.

        NOTE: This method can raise ValueError when validation fails.
        """
        if len(self.value) < MIN_BCRYPT_HASH_LENGTH:
            msg = "Invalid bcrypt hash length"
            raise ValueError(msg)
        if not self.value.startswith("$2b$"):
            msg = "Invalid bcrypt hash format"
            raise ValueError(msg)
        return FlextResult[None].ok(None)


class FlextAuthToken(FlextValue):
    """Authentication token value object."""

    value: str = Field(...)  # No min_length to allow custom validation
    token_type: str = Field(default="Bearer")

    @override
    def __str__(self) -> str:
        """Return auth token."""
        return f"{self.token_type} {self.value}"

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate auth token domain rules - raises ValueError."""
        if not self.value:
            msg = "Auth token value cannot be empty"
            raise ValueError(msg)
        if not self.token_type:
            msg = "Token type cannot be empty"
            raise ValueError(msg)
        if len(self.value) < MIN_AUTH_TOKEN_LENGTH:
            msg = "Auth token must be at least 10 characters"
            raise ValueError(msg)
        return FlextResult[None].ok(None)


# =============================================================================
# REFACTORING: Template Method Pattern - eliminates 22 lines duplication
# =============================================================================


class FlextBaseTokenValueObject(FlextValue):
    """Base token value object - Template Method Pattern for DRY principle.

    Eliminates massive code duplication between token value objects using
    SOLID principles. Template Method Pattern defines the skeleton of validation
    algorithm while allowing subclasses to customize specific steps.
    """

    value: str = Field(
        ...,
    )  # No min_length to allow custom validation in validate_business_rules

    @override
    def __str__(self) -> str:
        """Return protected token representation - Template Method."""
        return f"[{self._get_token_display_name()}]"

    @override
    def __repr__(self) -> str:
        """Return protected token class representation - Template Method."""
        return f"{self._get_token_class_name()}([PROTECTED])"

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Template Method: validates common rules + specific rules.

        NOTE: Production validation - errors raise ValueError for proper handling
        while still supporting FlextResult pattern.
        """
        # Validate common rules (DRY principle)
        self._validate_common_rules()

        # Template Method: delegate specific validation to subclasses
        return self._validate_specific_rules()

    def _validate_common_rules(self) -> None:
        """Apply common validation rules."""
        if not self.value:
            msg: str = f"{self._get_token_type_name()} cannot be empty"
            raise ValueError(msg)

    @override
    def _get_token_display_name(self) -> str:
        """Abstract method: get token display name for __str__."""
        msg = "Subclasses must implement _get_token_display_name"
        raise NotImplementedError(msg)

    @override
    def _get_token_class_name(self) -> str:
        """Abstract method: get token class name for __repr__."""
        msg = "Subclasses must implement _get_token_class_name"
        raise NotImplementedError(msg)

    @override
    def _get_token_type_name(self) -> str:
        """Abstract method: get token type name for error messages."""
        msg = "Subclasses must implement _get_token_type_name"
        raise NotImplementedError(msg)

    @override
    def _validate_specific_rules(self) -> FlextResult[None]:
        """Abstract method: validate token-specific rules."""
        # Base implementation has no specific rules
        return FlextResult[None].ok(None)


class FlextRefreshToken(FlextBaseTokenValueObject):
    """Refresh token value object - inherits common behavior from base."""

    @override
    def _get_token_display_name(self) -> str:
        """Return token display name."""
        return "REFRESH_TOKEN"

    @override
    def _get_token_class_name(self) -> str:
        """Return token class name."""
        return "RefreshToken"

    @override
    def _get_token_type_name(self) -> str:
        """Return token type name."""
        return "Refresh token value"

    @override
    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate refresh token specific rules - raises ValueError."""
        if len(self.value) < MIN_REFRESH_TOKEN_LENGTH:
            msg = "Refresh token must be at least 32 characters"
            raise ValueError(msg)
        return FlextResult[None].ok(None)


class FlextSessionToken(FlextBaseTokenValueObject):
    """Session token value object - inherits common behavior from base."""

    @override
    def _get_token_display_name(self) -> str:
        """Return token display name."""
        return "SESSION_TOKEN"

    @override
    def _get_token_class_name(self) -> str:
        """Return token class name."""
        return "FlextSessionToken"

    @override
    def _get_token_type_name(self) -> str:
        """Return token type name."""
        return "Session token value"

    @override
    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate session token specific rules - raises ValueError."""
        if len(self.value) < MIN_SESSION_TOKEN_LENGTH:
            msg = "Session token must be at least 16 characters"
            raise ValueError(msg)
        return FlextResult[None].ok(None)


class FlextIPAddress(FlextValue):
    """IP address value object with validation."""

    value: str = Field(..., min_length=7, max_length=45)  # IPv4 or IPv6

    @field_validator("value")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        """Validate IP address format."""
        try:
            ipaddress.ip_address(v)
        except ValueError as e:
            msg: str = f"Invalid IP address: {e}"
            raise ValueError(msg) from e
        else:
            return v

    @override
    def __str__(self) -> str:
        """Return user agent."""
        return self.value

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate IP address domain rules and business constraints."""
        try:
            ipaddress.ip_address(self.value)
            return FlextResult[None].ok(None)
        except ValueError as e:
            msg: str = f"Invalid IP address: {e}"
            return FlextResult[None].fail(msg)


class FlextUserAgent(FlextValue):
    """User agent value object."""

    value: str = Field(
        ...,
    )  # No max_length to allow custom validation in validate_business_rules

    @override
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

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate user agent domain rules - raises ValueError."""
        if not self.value:
            msg = "User agent cannot be empty"
            raise ValueError(msg)
        if len(self.value) > MAX_USER_AGENT_LENGTH:
            msg = "User agent must be at most 500 characters"
            raise ValueError(msg)
        return FlextResult[None].ok(None)


class FlextPasswordResetToken(FlextBaseTokenValueObject):
    """Password reset token value object - inherits common behavior from base."""

    value: str = Field(..., min_length=32)

    @override
    def _get_token_display_name(self) -> str:
        """Return token display name."""
        return "RESET_TOKEN"

    @override
    def _get_token_class_name(self) -> str:
        """Return token class name."""
        return "PasswordResetToken"

    @override
    def _get_token_type_name(self) -> str:
        """Return token type name."""
        return "Password reset token"

    @override
    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate password reset token specific rules."""
        if len(self.value) < MIN_PASSWORD_RESET_TOKEN_LENGTH:
            msg = "Password reset token must be at least 32 characters"
            return FlextResult[None].fail(msg)
        return FlextResult[None].ok(None)


class FlextEmailVerificationToken(FlextBaseTokenValueObject):
    """Email verification token value object - inherits common behavior from base."""

    value: str = Field(..., min_length=32)

    @override
    def _get_token_display_name(self) -> str:
        """Return token display name."""
        return "VERIFICATION_TOKEN"

    @override
    def _get_token_class_name(self) -> str:
        """Return token class name."""
        return "EmailVerificationToken"

    @override
    def _get_token_type_name(self) -> str:
        """Return token type name."""
        return "Email verification token"

    @override
    def _validate_specific_rules(self) -> FlextResult[None]:
        """Validate email verification token specific rules."""
        if len(self.value) < MIN_EMAIL_VERIFICATION_TOKEN_LENGTH:
            msg = "Email verification token must be at least 32 characters"
            return FlextResult[None].fail(msg)
        return FlextResult[None].ok(None)


class FlextJWTClaims(FlextValue):
    """JWT claims value object."""

    sub: str = Field(..., description="Subject (user ID)")
    username: str | None = Field(default=None, description="Username")
    role: str | None = Field(default=None, description="User role")
    permissions: list[str] = Field(default_factory=list, description="User permissions")
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

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate JWT claims domain rules .

        SOLID REFACTORING: Reduced from 6 returns to 2 returns using
        Railway-Oriented Programming + Strategy Pattern.
        """
        # Railway-Oriented Programming: Chain validations with early exit
        validation_errors = self._collect_validation_errors()

        if validation_errors:
            raise ValueError(validation_errors[0])

        return FlextResult[None].ok(None)

    def _collect_validation_errors(self) -> list[str]:
        """DRY helper: Collect all validation errors using Strategy Pattern."""

        # Define validation functions with explicit types
        def check_empty_sub() -> bool:
            return not self.sub

        def check_invalid_iat() -> bool:
            return self.iat <= 0

        def check_invalid_exp() -> bool:
            return self.exp <= 0

        def check_exp_before_iat() -> bool:
            return self.exp <= self.iat

        def check_invalid_token_type() -> bool:
            return self.token_type not in {"access", "refresh"}

        validators = [
            (check_empty_sub, "JWT subject (sub) cannot be empty"),
            (check_invalid_iat, "JWT issued at (iat) must be positive"),
            (check_invalid_exp, "JWT expiration (exp) must be positive"),
            (check_exp_before_iat, "JWT expiration must be after issued time"),
            (check_invalid_token_type, "JWT token type must be 'access' or 'refresh'"),
        ]

        return [error_msg for condition, error_msg in validators if condition()]


class FlextSecurityContext(FlextValue):
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

    @override
    def validate_business_rules(self) -> FlextResult[None]:
        """Validate security context domain rules - raises ValueError."""
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
        return FlextResult[None].ok(None)

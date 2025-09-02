"""FLEXT Auth Utilities - Utility classes and helper methods.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
import string
from collections.abc import Callable
from datetime import UTC, datetime

from flext_core import FlextResult

from flext_auth.constants import FlextAuthConstants
from flext_auth.core import FlextAuth
from flext_auth.services import FlextJWTService, FlextPasswordService
from flext_auth.typings import FlextAuthTypes


class FlextAuthUtilities:
    """Authentication utilities consolidated class."""

    @staticmethod
    def validate_username(username: FlextAuthTypes.Username) -> FlextResult[None]:
        """Validate username format."""
        if (
            not username
            or len(username.strip()) < FlextAuthConstants.MIN_USERNAME_LENGTH
        ):
            return FlextResult[None].fail("Username must be at least 3 characters")
        if len(username.strip()) > FlextAuthConstants.MAX_USERNAME_LENGTH:
            return FlextResult[None].fail("Username must be at most 50 characters")
        if not username.replace("_", "").isalnum():
            return FlextResult[None].fail(
                "Username can only contain letters, numbers, and underscores"
            )
        return FlextResult[None].ok(None)

    @staticmethod
    def validate_email(email: FlextAuthTypes.String) -> FlextResult[bool]:
        """Validate email format."""
        if "@" not in email or "." not in email.split("@")[-1]:
            return FlextResult[bool].fail("Invalid email format")
        if email.count("@") != 1:
            return FlextResult[bool].fail("Invalid email format")
        local, domain = email.split("@")
        if not local or not domain:
            return FlextResult[bool].fail("Invalid email format")
        if ".." in email:
            return FlextResult[bool].fail("Invalid email format")
        valid = True
        return FlextResult[bool].ok(valid)

    @staticmethod
    def generate_secure_password(length: int = 16) -> str:
        """Generate a secure password."""
        length = max(length, 8)

        # Character sets
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*(),.?":{}|<>'

        # Ensure at least one of each type
        password = [
            secrets.choice(lowercase),
            secrets.choice(uppercase),
            secrets.choice(digits),
            secrets.choice(special),
        ]

        # Fill the rest randomly
        all_chars = lowercase + uppercase + digits + special
        password.extend(secrets.choice(all_chars) for _ in range(length - 4))

        # Shuffle the password
        secrets.SystemRandom().shuffle(password)

        return "".join(password)

    @staticmethod
    def generate_session_id() -> FlextAuthTypes.SessionId:
        """Generate secure session ID."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def create_audit_context(
        user_id: FlextAuthTypes.UserId,
        action: FlextAuthTypes.String,
        source: FlextAuthTypes.String,
    ) -> FlextAuthTypes.Dict:
        """Create audit context."""
        return {
            "user_id": user_id,
            "action": action,
            "source": source,
            "timestamp": datetime.now(UTC).isoformat(),
        }

    @staticmethod
    def quick_start(
        *,
        create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
        REDACTED_LDAP_BIND_PASSWORD_username: FlextAuthTypes.Username = "REDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_password: FlextAuthTypes.String | None = None,
    ) -> FlextAuth:
        """Create FlextAuth instance with optional REDACTED_LDAP_BIND_PASSWORD user."""
        return FlextAuth.quick_start(
            create_REDACTED_LDAP_BIND_PASSWORD=create_REDACTED_LDAP_BIND_PASSWORD,
            REDACTED_LDAP_BIND_PASSWORD_username=REDACTED_LDAP_BIND_PASSWORD_username,
            REDACTED_LDAP_BIND_PASSWORD_password=REDACTED_LDAP_BIND_PASSWORD_password,
        )

    @staticmethod
    def hash_password(
        password: FlextAuthTypes.String, rounds: int = 12
    ) -> FlextResult[str]:
        """Hash password using FlextPasswordService."""
        service = FlextPasswordService()
        return service.hash_password(password, rounds)

    @staticmethod
    def generate_jwt(
        claims: FlextAuthTypes.Dict,
        expiry_minutes: int = 30,
        secret: FlextAuthTypes.AccessToken | None = None,
    ) -> FlextResult[str]:
        """Generate JWT token using FlextJWTService."""
        jwt_secret = secret or FlextAuthConstants.DEFAULT_JWT_SECRET
        return FlextJWTService.generate_token_static(jwt_secret, claims, expiry_minutes)

    @staticmethod
    def validate_jwt(
        token: FlextAuthTypes.AccessToken, secret: FlextAuthTypes.AccessToken | None = None
    ) -> FlextResult[FlextAuthTypes.TokenPayload]:
        """Validate JWT token using FlextJWTService."""
        jwt_secret = secret or FlextAuthConstants.DEFAULT_JWT_SECRET
        return FlextJWTService.validate_token_static(jwt_secret, token)


# Legacy compatibility functions for examples
def flext_auth_quick_start(
    *,
    create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
    REDACTED_LDAP_BIND_PASSWORD_username: FlextAuthTypes.Username = "REDACTED_LDAP_BIND_PASSWORD",
    REDACTED_LDAP_BIND_PASSWORD_password: FlextAuthTypes.String | None = None,
) -> FlextAuth:
    """Create FlextAuth instance with optional REDACTED_LDAP_BIND_PASSWORD user."""
    return FlextAuth.quick_start(
        create_REDACTED_LDAP_BIND_PASSWORD=create_REDACTED_LDAP_BIND_PASSWORD,
        REDACTED_LDAP_BIND_PASSWORD_username=REDACTED_LDAP_BIND_PASSWORD_username,
        REDACTED_LDAP_BIND_PASSWORD_password=REDACTED_LDAP_BIND_PASSWORD_password,
    )


def flext_auth_hash_password(
    password: FlextAuthTypes.String, rounds: int = 12
) -> FlextResult[str]:
    """Hash password using FlextPasswordService."""
    return FlextAuthUtilities.hash_password(password, rounds)


def flext_auth_generate_jwt(
    *,
    user_id: FlextAuthTypes.UserId,
    username: FlextAuthTypes.Username,
    role: FlextAuthTypes.UserRole,
    session_id: FlextAuthTypes.SessionId,
    jwt_secret: FlextAuthTypes.AccessToken,
    expiry_minutes: int = 30,
) -> FlextResult[FlextAuthTypes.AccessToken]:
    """Generate JWT token using FlextJWTService."""
    claims: FlextAuthTypes.Dict = {
        "sub": user_id,
        "username": username,
        "role": role,
        "session_id": session_id,
    }
    return FlextAuthUtilities.generate_jwt(claims, expiry_minutes, jwt_secret)


def flext_auth_validate_jwt(
    token: FlextAuthTypes.AccessToken, jwt_secret: FlextAuthTypes.AccessToken
) -> FlextResult[FlextAuthTypes.TokenPayload]:
    """Validate JWT token using FlextJWTService."""
    return FlextAuthUtilities.validate_jwt(token, jwt_secret)


def flext_auth_validate_email(email: FlextAuthTypes.String) -> FlextResult[bool]:
    """Validate email format."""
    return FlextAuthUtilities.validate_email(email)


def generate_secure_password(length: int = 16) -> str:
    """Generate a secure password."""
    return FlextAuthUtilities.generate_secure_password(length)


def generate_secure_token(length: int = 32) -> str:
    """Generate secure token."""
    return secrets.token_urlsafe(length)


# Decorators for compatibility (placeholder implementations)
def flext_auth_required(func: Callable[[object], object]) -> Callable[[object], object]:
    """Authentication required decorator."""

    def wrapper(arg: object) -> object:
        return func(arg)

    return wrapper


def flext_auth_role_required(
    _required_role: FlextAuthTypes.UserRole,
) -> Callable[[Callable[[object], object]], Callable[[object], object]]:
    """Role required decorator."""

    def decorator(func: Callable[[object], object]) -> Callable[[object], object]:
        def wrapper(arg: object) -> object:
            return func(arg)

        return wrapper

    return decorator


def flext_auth_permission_required(
    _required_permission: FlextAuthTypes.Permission,
) -> Callable[[Callable[[object], object]], Callable[[object], object]]:
    """Permission required decorator."""

    def decorator(func: Callable[[object], object]) -> Callable[[object], object]:
        def wrapper(arg: object) -> object:
            return func(arg)

        return wrapper

    return decorator


def create_auth_service() -> FlextAuth:
    """Create FlextAuth service instance."""
    return FlextAuth()


__all__ = [
    "FlextAuthUtilities",
    "create_auth_service",
    "flext_auth_generate_jwt",
    "flext_auth_hash_password",
    "flext_auth_permission_required",
    "flext_auth_quick_start",
    "flext_auth_required",
    "flext_auth_role_required",
    "flext_auth_validate_email",
    "flext_auth_validate_jwt",
    "generate_secure_password",
    "generate_secure_token",
]

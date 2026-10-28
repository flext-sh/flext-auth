"""Authentication validation and credential utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

import bcrypt
from flext_api import r, u

from flext_auth import c, p


class FlextAuthUtilitiesAuthValidation:
    """Validation and credential helpers for the auth domain."""

    @staticmethod
    def validate_email(email: str) -> p.Result[str]:
        """Validate email format.

        Args:
            email: Candidate email address.

        Returns:
            The trimmed email; failure when empty, too long, or malformed.

        """
        if not email or not email.strip():
            return r[str].fail("Email cannot be empty")
        email = email.strip()
        if len(email) > c.Auth.MAX_EMAIL_LENGTH:
            return r[str].fail(f"Email too long (max {c.Auth.MAX_EMAIL_LENGTH} chars)")
        if "@" not in email or "." not in email.split("@")[1]:
            return r[str].fail("Invalid email format")
        return r[str].ok(email)

    @staticmethod
    def validate_password(password: str) -> p.Result[str]:
        """Validate password strength.

        Args:
            password: Candidate credential.

        Returns:
            The credential; failure when empty or outside the configured
            length bounds.

        """
        if not password:
            return r[str].fail("Password cannot be empty")
        min_length = c.Auth.CREDENTIALS_PASSWORD_MIN_LENGTH
        max_length = c.Auth.CREDENTIALS_PASSWORD_MAX_LENGTH
        if len(password) < min_length:
            return r[str].fail(f"Password too short (min {min_length} chars)")
        if len(password) > max_length:
            return r[str].fail(f"Password too long (max {max_length} chars)")
        return r[str].ok(password)

    @staticmethod
    def validate_username(username: str) -> p.Result[str]:
        """Validate username with auth-specific rules.

        Args:
            username: Candidate account name.

        Returns:
            The trimmed username; failure when empty or outside the
            configured length bounds.

        """
        if not username or not username.strip():
            return r[str].fail("Username cannot be empty")
        username = username.strip()
        min_length = c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH
        max_length = c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH
        if len(username) < min_length:
            return r[str].fail(f"Username too short (min {min_length} chars)")
        if len(username) > max_length:
            return r[str].fail(f"Username too long (max {max_length} chars)")
        return r[str].ok(username)

    @staticmethod
    def calculate_expiry_time(minutes: int) -> datetime:
        """Calculate token/session expiry time.

        Args:
            minutes: Lifetime from now, in minutes.

        Returns:
            The UTC timestamp marking the expiry.

        """
        current_time: datetime = u.generate_datetime_utc()
        return current_time + timedelta(minutes=minutes)

    @staticmethod
    def generate_session_id() -> str:
        """Generate a secure session ID.

        Returns:
            A cryptographically random hexadecimal session identifier.

        """
        return secrets.token_hex(16)

    @staticmethod
    def expired(expiry_time: datetime) -> bool:
        """Check if a timestamp is expired.

        Args:
            expiry_time: Timestamp to test against the current time.

        Returns:
            Whether the timestamp is already in the past.

        """
        current_time: datetime = u.now()
        return current_time > expiry_time

    @staticmethod
    def hash_password(password: str, *, rounds: int | None = None) -> str:
        """Hash a password using bcrypt.

        Args:
            password: Plain credential to hash.
            rounds: Explicit domain policy, or the existing default when omitted.

        Returns:
            Salted bcrypt hash of the credential.

        """
        salt = bcrypt.gensalt(
            rounds=c.Auth.DEFAULT_HASH_ROUNDS if rounds is None else rounds,
        )
        return bcrypt.hashpw(password.encode(), salt).decode()

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain credential to check.
            hashed: Stored bcrypt hash to compare against.

        Returns:
            Whether the credential matches the stored hash.

        """
        return bcrypt.checkpw(password.encode(), hashed.encode())


__all__: list[str] = ["FlextAuthUtilitiesAuthValidation"]

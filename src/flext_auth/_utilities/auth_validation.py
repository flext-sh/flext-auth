"""Authentication validation and credential utilities."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta

import bcrypt

from flext_api import r, u
from flext_auth import c, p


class FlextAuthUtilitiesAuthValidation:
    @staticmethod
    def validate_email(email: str) -> p.Result[str]:
        """Validate email format."""
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
        """Validate password strength."""
        if not password:
            return r[str].fail("Password cannot be empty")
        if len(password) < c.Auth.CREDENTIALS_PASSWORD_MIN_LENGTH:
            return r[str].fail(
                f"Password too short (min {c.Auth.CREDENTIALS_PASSWORD_MIN_LENGTH} chars)"
            )
        if len(password) > c.Auth.CREDENTIALS_PASSWORD_MAX_LENGTH:
            return r[str].fail(
                f"Password too long (max {c.Auth.CREDENTIALS_PASSWORD_MAX_LENGTH} chars)"
            )
        return r[str].ok(password)

    @staticmethod
    def validate_username(username: str) -> p.Result[str]:
        """Validate username with auth-specific rules."""
        if not username or not username.strip():
            return r[str].fail("Username cannot be empty")
        username = username.strip()
        if len(username) < c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH:
            return r[str].fail(
                f"Username too short (min {c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH} chars)"
            )
        if len(username) > c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH:
            return r[str].fail(
                f"Username too long (max {c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH} chars)"
            )
        return r[str].ok(username)

    @staticmethod
    def calculate_expiry_time(minutes: int) -> datetime:
        """Calculate token/session expiry time."""
        current_time: datetime = u.generate_datetime_utc()
        return current_time + timedelta(minutes=minutes)

    @staticmethod
    def generate_session_id() -> str:
        """Generate a secure session ID."""
        return secrets.token_hex(16)

    @staticmethod
    def expired(expiry_time: datetime) -> bool:
        """Check if a timestamp is expired."""
        current_time: datetime = u.now()
        return current_time > expiry_time

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt(rounds=c.Auth.DEFAULT_HASH_ROUNDS)
        return bcrypt.hashpw(password.encode(), salt).decode()

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        return bcrypt.checkpw(password.encode(), hashed.encode())


__all__: list[str] = ["FlextAuthUtilitiesAuthValidation"]

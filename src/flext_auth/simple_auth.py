"""Simple Authentication Functions with Production-Ready Security."""

from __future__ import annotations

import secrets
from datetime import datetime, timedelta
from typing import Any

import bcrypt

from flext_auth.core import ServiceResult


def hash_password(password: str, rounds: int = 12) -> str:
    """Hash a password using bcrypt with proper salt.

    Args:
        password: Plain text password to hash
        rounds: Number of bcrypt rounds (default 12 for production)

    Returns:
        Bcrypt hash that can be stored in database

    """
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=rounds)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against bcrypt hash.

    Args:
        password: Plain text password to verify
        stored_hash: Stored bcrypt hash from database

    Returns:
        True if password matches, False otherwise

    """
    try:
        password_bytes = password.encode("utf-8")
        stored_hash_bytes = stored_hash.encode("utf-8")
        return bcrypt.checkpw(password_bytes, stored_hash_bytes)
    except (ValueError, TypeError):
        return False


def create_session(
    user_id: str, expires_minutes: int = 60
) -> ServiceResult[dict[str, Any]]:
    """Create a simple session."""
    try:
        session_id = secrets.token_urlsafe(32)
        now = datetime.now()
        expires_at = now + timedelta(minutes=expires_minutes)

        session = {
            "session_id": session_id,
            "user_id": user_id,
            "created_at": now.isoformat(),
            "expires_at": expires_at.isoformat(),
            "active": True,
        }

        return ServiceResult.ok(session)
    except Exception as e:
        return ServiceResult.fail(f"Session creation failed: {e}")


def validate_session(session: dict[str, Any]) -> ServiceResult[bool]:
    """Validate if session is still active."""
    try:
        if not session.get("active", False):
            return ServiceResult.fail("Session is inactive")

        expires_str = session.get("expires_at")
        if not expires_str:
            return ServiceResult.fail("Session has no expiration")

        expires_at = datetime.fromisoformat(expires_str)
        if datetime.now() > expires_at:
            return ServiceResult.fail("Session has expired")

        return ServiceResult.ok(True)
    except Exception as e:
        return ServiceResult.fail(f"Session validation failed: {e}")


def create_user(
    username: str, password: str, email: str = ""
) -> ServiceResult[dict[str, Any]]:
    """Create a simple user record."""
    try:
        user_id = secrets.token_urlsafe(16)
        password_hash = hash_password(password)

        user = {
            "user_id": user_id,
            "username": username,
            "email": email,
            "password_hash": password_hash,
            "created_at": datetime.now().isoformat(),
            "active": True,
        }

        return ServiceResult.ok(user)
    except Exception as e:
        return ServiceResult.fail(f"User creation failed: {e}")


def authenticate_user(
    username: str, password: str, users: dict[str, dict[str, Any]]
) -> ServiceResult[dict[str, Any]]:
    """Authenticate user against a users dictionary."""
    try:
        user = users.get(username)
        if not user:
            return ServiceResult.fail("User not found")

        if not user.get("active", False):
            return ServiceResult.fail("User is inactive")

        stored_hash = user.get("password_hash", "")
        if not verify_password(password, stored_hash):
            return ServiceResult.fail("Invalid password")

        # Return user without password hash
        safe_user = {k: v for k, v in user.items() if k != "password_hash"}
        return ServiceResult.ok(safe_user)
    except Exception as e:
        return ServiceResult.fail(f"Authentication failed: {e}")

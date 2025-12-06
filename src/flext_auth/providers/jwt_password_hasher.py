"""FLEXT Auth JWT Password Hasher - Dedicated password hashing service.

This module provides a dedicated service for password hashing operations following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

import bcrypt
from flext_core import r

if TYPE_CHECKING:
    from flext_auth.providers.jwt import FlextAuthJwtProvider


class FlextAuthPasswordHasher:
    """Dedicated password hashing service.

    Single responsibility: Handle password hashing and verification operations.
    Uses bcrypt for secure password hashing with configurable rounds.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def hash_password(self, password: str) -> r[str]:
        """Hash password using bcrypt with railway-oriented programming.

        Args:
        password: Plain text password to hash

        Returns:
        FlextResult containing hashed password or error

        """
        try:
            salt_rounds = 12
            salt = bcrypt.gensalt(rounds=salt_rounds)
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
            return r.ok(hashed.decode("utf-8"))

        except Exception as e:
            return r.fail(f"Password hashing failed: {e}")

    def verify_password(self, password: str, hashed_password: str) -> r[bool]:
        """Verify password against hash using bcrypt.

        Args:
        password: Plain text password to verify
        hashed_password: Hashed password to check against

        Returns:
        r containing verification result or error

        """
        try:
            result = bcrypt.checkpw(
                password.encode("utf-8"),
                hashed_password.encode("utf-8"),
            )
            return r.ok(result)

        except Exception as e:
            return r.fail(f"Password verification failed: {e}")


__all__ = ["FlextAuthPasswordHasher"]

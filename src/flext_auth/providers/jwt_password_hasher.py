"""FLEXT Auth JWT Password Hasher - Dedicated password hashing service.

This module provides a dedicated service for password hashing operations following
SOLID principles with railway-oriented programming and flext-core patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import FlextAuthJwtProvider, p, u


class FlextAuthPasswordHasher:
    """Dedicated password hashing service.

    Single responsibility: Handle password hashing and verification operations.
    Uses bcrypt for secure password hashing with configurable rounds.
    """

    def __init__(self, provider: FlextAuthJwtProvider) -> None:
        """Initialize with provider reference for configuration access."""
        self._provider = provider

    def hash_password(self, password: str) -> p.Result[str]:
        """Hash password using bcrypt with railway-oriented programming.

        Args:
        password: Plain text password to hash

        Returns:
        r containing hashed password or error

        """

        def _hash() -> str:
            return u.Auth.hash_password(password)

        return u.try_(
            _hash,
            catch=(ValueError, TypeError),
        ).map_error(lambda exc: f"Password hashing failed: {type(exc).__name__}: {exc}")

    def verify_password(self, password: str, hashed_password: str) -> p.Result[bool]:
        """Verify password against hash using bcrypt.

        Args:
        password: Plain text password to verify
        hashed_password: Hashed password to check against

        Returns:
        r containing verification result or error

        """

        def _verify() -> bool:
            return u.Auth.verify_password(password, hashed_password)

        return u.try_(
            _verify,
            catch=(ValueError, TypeError),
        ).map_error(
            lambda exc: f"Password verification failed: {type(exc).__name__}: {exc}"
        )


__all__: list[str] = ["FlextAuthPasswordHasher"]

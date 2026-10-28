"""Authentication password model helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

import bcrypt

from flext_auth import c


class FlextAuthModelsAuthCredential:
    """Credential model namespace for password hashing helpers."""

    class PasswordUtil:
        """Password utilities for authentication."""

        @staticmethod
        def hash_password(password: str) -> str:
            """Hash a password using bcrypt.

            Args:
                password: Plain credential to hash.

            Returns:
                Salted bcrypt hash of the credential.

            """
            salt = bcrypt.gensalt(rounds=c.Auth.CREDENTIALS_PASSWORD_BCRYPT_ROUNDS)
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


__all__: list[str] = ["FlextAuthModelsAuthCredential"]

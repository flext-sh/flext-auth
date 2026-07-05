"""Authentication password model helpers."""

from __future__ import annotations

import bcrypt

from flext_auth import c


class FlextAuthModelsAuthPassword:
    class PasswordUtil:
        """Password utilities for authentication."""

        @staticmethod
        def hash_password(password: str) -> str:
            """Hash a password using bcrypt."""
            salt = bcrypt.gensalt(rounds=c.Auth.CREDENTIALS_PASSWORD_BCRYPT_ROUNDS)
            return bcrypt.hashpw(password.encode(), salt).decode()

        @staticmethod
        def verify_password(password: str, hashed: str) -> bool:
            """Verify a password against its hash."""
            return bcrypt.checkpw(password.encode(), hashed.encode())


__all__: list[str] = ["FlextAuthModelsAuthPassword"]

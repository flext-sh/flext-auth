"""Security utilities for authentication and authorization.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

This module provides security utilities including password hashing,
token generation, and JWT handling for the FLEXT authentication system.
"""

from __future__ import annotations

import secrets
from typing import Any, Protocol, runtime_checkable

import jwt
from passlib.context import CryptContext

# Type aliases for security components
Hash = str
Salt = str
Token = str


@runtime_checkable
class HashingProtocol(Protocol):
    """Protocol for password hashing implementations."""

    def hash(self, password: str) -> str:
        """Hash a password."""
        ...

    def verify(self, password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        ...


class PasswordHasher:
    """Password hashing utility using Argon2."""

    def __init__(self) -> None:
        """Initialize password hasher with Argon2 configuration."""
        self.context = CryptContext(
            schemes=["argon2"],
            default="argon2",
            argon2__memory_cost=65536,  # 64MB
            argon2__time_cost=3,  # 3 iterations
            argon2__parallelism=4,  # 4 threads
        )

    def hash(self, password: str) -> str:
        """Hash a password using Argon2.

        Args:
            password: Plain text password to hash.

        Returns:
            Hashed password string.

        Raises:
            ValueError: If password hashing fails.

        """
        try:
            return self.context.hash(password)
        except (ValueError, TypeError, RuntimeError, AttributeError, OSError) as e:
            # ZERO TOLERANCE - Specific exception types for password hashing failures
            msg = f"Failed to hash password: {e}"
            raise ValueError(msg) from e

    def verify(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain text password to verify.
            hashed_password: Hashed password to verify against.

        Returns:
            True if password matches hash, False otherwise.

        """
        try:
            return self.context.verify(password, hashed_password)
        except (ValueError, TypeError, RuntimeError, AttributeError, OSError):
            # ZERO TOLERANCE - Specific exception types for password verification failures
            return False

    def needs_update(self, hashed_password: str) -> bool:
        """Check if a password hash needs to be updated.

        Args:
            hashed_password: The hashed password to check.

        Returns:
            True if the hash should be updated, False otherwise.

        """
        return self.context.needs_update(hashed_password)


class TokenGenerator:
    """Token generation utility."""

    def generate(self, length: int = 32) -> str:
        """Generate a cryptographically secure token.

        Args:
            length: Length of the token in bytes.

        Returns:
            Hex-encoded token string (length * 2 characters).

        """
        return secrets.token_hex(length)

    def generate_jwt(
        self,
        payload: dict[str, Any],
        secret: str,
        algorithm: str = "HS256",
    ) -> str:
        """Generate a JWT token.

        Args:
            payload: JWT payload data.
            secret: Secret key for signing.
            algorithm: Signing algorithm.

        Returns:
            Encoded JWT token string.

        """
        return str(jwt.encode(payload, secret, algorithm=algorithm))

    def verify_jwt(
        self,
        token: str,
        secret: str,
        algorithm: str = "HS256",
    ) -> dict[str, Any] | None:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify.
            secret: Secret key for verification.
            algorithm: Signing algorithm.

        Returns:
            Decoded payload if valid, None if invalid.

        """
        try:
            return jwt.decode(token, secret, algorithms=[algorithm])
        except jwt.InvalidTokenError:
            return None


def generate_secure_token(length: int = 32) -> str:
    """Generate a cryptographically secure token.

    Args:
        length: Length of the token in bytes.

    Returns:
        Hex-encoded token string (length * 2 characters).

    """
    return secrets.token_hex(length)


class SecurityManager:
    """Security manager that coordinates password hashing and token generation."""

    def __init__(self) -> None:
        """Initialize security manager with password hasher and token generator."""
        self.password_hasher = PasswordHasher()
        self.token_generator = TokenGenerator()

    def hash_password(self, password: str) -> str:
        """Hash a password using the password hasher.

        Args:
            password: Plain text password to hash.

        Returns:
            Hashed password string.

        """
        return self.password_hasher.hash(password)

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain text password to verify.
            hashed_password: Hashed password to verify against.

        Returns:
            True if password matches hash, False otherwise.

        """
        return self.password_hasher.verify(password, hashed_password)

    def generate_token(self, length: int = 32) -> str:
        """Generate a secure token.

        Args:
            length: Length of the token in bytes.

        Returns:
            Hex-encoded token string.

        """
        return self.token_generator.generate(length)

    def generate_jwt(
        self,
        payload: dict[str, Any],
        secret: str,
        algorithm: str = "HS256",
    ) -> str:
        """Generate a JWT token.

        Args:
            payload: JWT payload data.
            secret: Secret key for signing.
            algorithm: Signing algorithm.

        Returns:
            Encoded JWT token string.

        """
        return self.token_generator.generate_jwt(payload, secret, algorithm)

    def verify_jwt(
        self,
        token: str,
        secret: str,
        algorithm: str = "HS256",
    ) -> dict[str, Any] | None:
        """Verify and decode a JWT token.

        Args:
            token: JWT token to verify.
            secret: Secret key for verification.
            algorithm: Signing algorithm.

        Returns:
            Decoded payload if valid, None if invalid.

        """
        try:
            return self.token_generator.verify_jwt(token, secret, algorithm)
        except jwt.InvalidTokenError:
            return None

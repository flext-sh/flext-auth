"""FLEXT Auth Utilities - JWT and password processing utilities.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from datetime import datetime

import bcrypt
import jwt
from flext_core import FlextResult, FlextTypes
from pydantic import SecretStr

from flext_auth.constants import FlextAuthConstants


class FlextAuthUtilities:
    """Auth utilities class with JWT and password processing."""

    class PasswordProcessing:
        """Password hashing and verification utilities using bcrypt."""

        @staticmethod
        def hash_password(
            password: str,
            rounds: int = FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS,
        ) -> FlextResult[str]:
            """Hash password using bcrypt.

            Args:
                password: Plain text password to hash
                rounds: Number of bcrypt rounds (default from constants)

            Returns:
                FlextResult containing hashed password or error

            """
            try:
                password_bytes = password.encode("utf-8")
                salt = bcrypt.gensalt(rounds=rounds)
                hashed = bcrypt.hashpw(password_bytes, salt)
                return FlextResult[str].ok(hashed.decode("utf-8"))
            except Exception as e:
                return FlextResult[str].fail(f"Password hashing failed: {e}")

        @staticmethod
        def verify_password(password: str, password_hash: str) -> FlextResult[bool]:
            """Verify password against stored hash using bcrypt.

            Args:
                password: Plain text password to verify
                password_hash: Stored bcrypt hash

            Returns:
                FlextResult containing verification result or error

            """
            try:
                is_valid = bcrypt.checkpw(
                    password.encode("utf-8"), password_hash.encode("utf-8")
                )
                return FlextResult[bool].ok(is_valid)
            except Exception as e:
                return FlextResult[bool].fail(f"Password verification failed: {e}")

        @staticmethod
        def validate_password(password: str) -> FlextResult[FlextTypes.Dict]:
            """Validate password strength and return detailed results.

            Args:
                password: Password to validate

            Returns:
                FlextResult containing validation results dict

            """
            results = {
                "length": len(password),
                "min_length": FlextAuthConstants.Credentials.Password.MIN_LENGTH,
                "has_upper": any(c.isupper() for c in password),
                "has_lower": any(c.islower() for c in password),
                "has_digit": any(c.isdigit() for c in password),
                "is_weak": password.lower()
                in FlextAuthConstants.Credentials.Password.WEAK_PASSWORDS,
                "is_valid": True,
                "errors": [],
            }

            if len(password) < FlextAuthConstants.Credentials.Password.MIN_LENGTH:
                results["is_valid"] = False
                results["errors"].append(
                    f"Password must be at least {FlextAuthConstants.Credentials.Password.MIN_LENGTH} characters"
                )

            if not results["has_upper"]:
                results["is_valid"] = False
                results["errors"].append(
                    "Password must contain at least one uppercase letter"
                )

            if not results["has_lower"]:
                results["is_valid"] = False
                results["errors"].append(
                    "Password must contain at least one lowercase letter"
                )

            if not results["has_digit"]:
                results["is_valid"] = False
                results["errors"].append("Password must contain at least one digit")

            if results["is_weak"]:
                results["is_valid"] = False
                results["errors"].append("Password is too weak")

            return FlextResult[FlextTypes.Dict].ok(results)

    class JWTProcessing:
        """JWT token processing utilities."""

        @staticmethod
        def extract_claims(
            token: str, secret_key: SecretStr
        ) -> FlextResult[dict[str, str | int | float | bool | None]]:
            """Extract claims from JWT token.

            Args:
                token: JWT token
                secret_key: Secret key for verification

            Returns:
                FlextResult containing claims or error

            """
            try:
                decoded_payload = jwt.decode(
                    token,
                    secret_key.get_secret_value(),
                    algorithms=[FlextAuthConstants.Jwt.DEFAULT_ALGORITHM],
                    options={
                        "verify_exp": False,
                        "verify_aud": False,
                        "verify_iat": False,
                        "verify_nbf": False,
                    },
                )
                return FlextResult[dict[str, str | int | float | bool | None]].ok(
                    decoded_payload
                )
            except jwt.InvalidTokenError as e:
                return FlextResult[dict[str, str | int | float | bool | None]].fail(
                    f"Invalid token: {e}"
                )
            except Exception as e:
                return FlextResult[dict[str, str | int | float | bool | None]].fail(
                    f"Claims extraction failed: {e}"
                )

        @staticmethod
        def encode_token(
            payload: dict[str, str | int | float | bool | datetime | None],
            secret_key: str,
            algorithm: str = FlextAuthConstants.Jwt.DEFAULT_ALGORITHM,
        ) -> FlextResult[str]:
            """Encode JWT token with payload.

            Args:
                payload: Token payload data
                secret_key: Secret key for signing
                algorithm: JWT algorithm (default from constants)

            Returns:
                FlextResult containing encoded token or error

            """
            try:
                token_str = jwt.encode(payload, secret_key, algorithm=algorithm)
                return FlextResult[str].ok(token_str)
            except Exception as e:
                return FlextResult[str].fail(f"JWT encoding failed: {e}")

        @staticmethod
        def decode_token(
            token: str,
            secret_key: str,
            algorithm: str = FlextAuthConstants.Jwt.DEFAULT_ALGORITHM,
        ) -> FlextResult[dict[str, str | int | float | bool | None]]:
            """Decode JWT token and return payload.

            Args:
                token: JWT token string
                secret_key: Secret key for verification
                algorithm: JWT algorithm (default from constants)

            Returns:
                FlextResult containing decoded payload or error

            """
            try:
                decoded_payload = jwt.decode(
                    token,
                    secret_key,
                    algorithms=[algorithm],
                    options={
                        "verify_aud": False,
                        "verify_exp": False,
                        "verify_iat": False,
                        "verify_nbf": False,
                    },
                )
                return FlextResult[dict[str, str | int | float | bool | None]].ok(
                    decoded_payload
                )
            except Exception as e:
                return FlextResult[dict[str, str | int | float | bool | None]].fail(
                    f"JWT verification failed: {e}"
                )

    class TokenProcessing:
        """Token generation and processing utilities."""

        @staticmethod
        def generate_secure_token(length: int = 32) -> str:
            """Generate a secure random token.

            Args:
                length: Token length in bytes

            Returns:
                Secure random token string (hex encoded)

            """
            return secrets.token_hex(length)


__all__ = ["FlextAuthUtilities"]

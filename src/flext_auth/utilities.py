"""FlextAuth utilities - Advanced type-safe utilities using u patterns.

from flext_auth import u
Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta

import bcrypt
import jwt
from flext_api import r, u

from flext_auth import c, p, t
from flext_auth._utilities.managers import FlextAuthUtilitiesManagers


class FlextAuthUtilities(u, FlextAuthUtilitiesManagers):
    """FlextAuth advanced utilities extending u with domain-specific helpers."""

    class Auth:
        """Auth-specific utility namespace.

        This namespace groups all auth-specific utilities for better organization
        and cross-project access. Access via u.Auth.* pattern.

        Example:
            result = u.Auth.Collection.parse_sequence(Status, ["active", "pending"])
            validator = u.Auth.Collection.coerce_list_validator(Status)

        """

        @staticmethod
        def validate_email(email: str) -> p.Result[str]:
            """Validate email format."""
            if not email or not email.strip():
                return r[str].fail("Email cannot be empty")
            email = email.strip()
            if len(email) > c.Auth.MAX_EMAIL_LENGTH:
                return r[str].fail(
                    f"Email too long (max {c.Auth.MAX_EMAIL_LENGTH} chars)",
                )
            if "@" not in email or "." not in email.split("@")[1]:
                return r[str].fail("Invalid email format")
            return r[str].ok(email)

        @staticmethod
        def validate_password(password: str) -> p.Result[str]:
            """Validate password strength."""
            if not password:
                return r[str].fail("Password cannot be empty")
            if len(password) < c.Auth.CREDENTIALS_Password.MIN_LENGTH:
                return r[str].fail(
                    f"Password too short (min {c.Auth.CREDENTIALS_Password.MIN_LENGTH} chars)",
                )
            if len(password) > c.Auth.CREDENTIALS_Password.MAX_LENGTH:
                return r[str].fail(
                    f"Password too long (max {c.Auth.CREDENTIALS_Password.MAX_LENGTH} chars)",
                )
            return r[str].ok(password)

        @staticmethod
        def validate_username(username: str) -> p.Result[str]:
            """Validate username with auth-specific rules."""
            if not username or not username.strip():
                return r[str].fail("Username cannot be empty")
            username = username.strip()
            if len(username) < c.Auth.CREDENTIALS_Username.MIN_LENGTH:
                return r[str].fail(
                    f"Username too short (min {c.Auth.CREDENTIALS_Username.MIN_LENGTH} chars)",
                )
            if len(username) > c.Auth.CREDENTIALS_Username.MAX_LENGTH:
                return r[str].fail(
                    f"Username too long (max {c.Auth.CREDENTIALS_Username.MAX_LENGTH} chars)",
                )
            return r[str].ok(username)

        @staticmethod
        def calculate_expiry_time(minutes: int) -> datetime:
            """Calculate token/session expiry time."""
            return datetime.now(UTC) + timedelta(minutes=minutes)

        @staticmethod
        def generate_session_id() -> str:
            """Generate a secure session ID."""
            return secrets.token_hex(16)

        @staticmethod
        def expired(expiry_time: datetime) -> bool:
            """Check if a timestamp is expired."""
            return datetime.now(UTC) > expiry_time

        @staticmethod
        def hash_password(password: str) -> str:
            """Hash a password using bcrypt."""
            salt = bcrypt.gensalt(rounds=c.Auth.DEFAULT_HASH_ROUNDS)
            return bcrypt.hashpw(password.encode(), salt).decode()

        @staticmethod
        def verify_password(password: str, hashed: str) -> bool:
            """Verify a password against its hash."""
            return bcrypt.checkpw(password.encode(), hashed.encode())

        @staticmethod
        def build_auth_error_response(
            error: str,
            error_code: str = "AUTH_ERROR",
        ) -> t.ConfigurationMapping:
            """Build an authentication error response."""
            return {
                "success": False,
                "error": error,
                "error_code": error_code,
                "timestamp": datetime.now(UTC).isoformat(),
            }

        @staticmethod
        def build_auth_success_response(
            token: str | None = None,
            user_id: str | None = None,
            expires_at: datetime | None = None,
        ) -> t.ConfigurationMapping:
            """Build a successful authentication response."""
            response: t.MutableConfigurationMapping = {
                "success": True,
                "message": str(c.Auth.SUCCESS_AUTH_RESPONSE["message"]),
                "timestamp": datetime.now(UTC).isoformat(),
            }
            if token:
                response["token"] = token
            if user_id:
                response["user_id"] = user_id
            if expires_at:
                response["expires_at"] = expires_at.isoformat()
            return response

        @staticmethod
        def decode_token(
            token: str,
            secret: t.SecretStr,
            *,
            verify: bool = True,
            algorithms: t.VariadicTuple[str] | None = None,
            audience: str | None = None,
        ) -> p.Result[t.Auth.TokensClaimMap]:
            """Generic JWT token decoding.

            Args:
            token: JWT token to decode
            secret: Secret key for verification
            verify: Whether to verify signature
            audience: Expected audience claim for validation

            Returns:
            r with decoded payload or error

            """
            try:
                algorithms_list: t.StrSequence
                if algorithms is None:
                    algorithms_list = [c.Auth.JWT_DEFAULT_ALGORITHM]
                else:
                    algorithms_list = list(algorithms)
                payload = jwt.decode(
                    token,
                    secret.get_secret_value(),
                    algorithms=list(algorithms_list),
                    options={"verify_signature": verify},
                    audience=audience,
                )
                if not u.dict_like(payload):
                    return r[t.Auth.TokensClaimMap].fail(
                        "Decoded token payload is not a dictionary",
                    )
                typed_payload: t.Auth.TokensClaimMap = {
                    str(key): value for key, value in payload.items()
                }
                return r[t.Auth.TokensClaimMap].ok(typed_payload)
            except jwt.InvalidTokenError as exc:
                return r[t.Auth.TokensClaimMap].fail(f"Invalid token: {exc}")
            except c.ValidationError as exc:
                return r[t.Auth.TokensClaimMap].fail(
                    f"Decoded token payload validation failed: {exc}",
                )
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as exc:
                return r[t.Auth.TokensClaimMap].fail(f"Decoding failed: {exc}")

        @staticmethod
        def encode_token(
            payload: t.Auth.TokensClaimMap,
            secret: str,
            algorithm: str = c.Auth.JWT_DEFAULT_ALGORITHM,
        ) -> p.Result[str]:
            """Generic JWT token encoding.

            Args:
            payload: Token payload
            secret: Secret key for signing
            algorithm: JWT algorithm

            Returns:
            r with encoded token or error

            """
            try:
                encoded = jwt.encode(dict(payload), secret, algorithm=algorithm)
                return r[str].ok(encoded)
            except (
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ) as exc:
                return r[str].fail(f"Encoding failed: {exc}")


u = FlextAuthUtilities
__all__: t.MutableSequenceOf[str] = ["FlextAuthUtilities", "u"]

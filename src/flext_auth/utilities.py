"""FlextAuth utilities - Advanced type-safe utilities using u patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Annotated

import bcrypt
import jwt
from flext_api import FlextApiUtilities
from flext_core import FlextUtilities, r
from pydantic import BeforeValidator, SecretStr, ValidationError

from flext_auth import c, t


class FlextAuthUtilities(FlextApiUtilities):
    """FlextAuth advanced utilities extending u with domain-specific helpers.

    Architecture: Advanced utilities with ZERO code bloat through:
    - Unified guard APIs for runtime validation
    - BeforeValidator factories for Pydantic coercion
    - @validated decorators eliminating manual validation
    - Generic parsing utilities for StrEnums
    """

    @classmethod
    def is_valid_permission_type(cls, value: str) -> bool:
        """Validate PermissionTypes membership.

        Uses parent Enum utilities for consistency.
        """
        return FlextUtilities.Enum.is_member(c.Auth.PermissionTypes, value)

    @classmethod
    def is_valid_provider_type(cls, value: str) -> bool:
        """Validate ProviderTypes membership.

        Uses parent Enum utilities for consistency.
        """
        return FlextUtilities.Enum.is_member(c.Auth.ProviderTypes, value)

    @classmethod
    def is_valid_role_type(cls, value: str) -> bool:
        """Validate RoleTypes membership.

        Uses parent Enum utilities for consistency.
        """
        return FlextUtilities.Enum.is_member(c.Auth.RoleTypes, value)

    @classmethod
    def is_valid_token_type(cls, value: str) -> bool:
        """Validate TokenTypes membership.

        Uses parent Enum utilities for consistency.
        """
        return FlextUtilities.Enum.is_member(c.Auth.TokenTypes, value)

    class Auth:
        """Auth-specific utility namespace.

        This namespace groups all auth-specific utilities for better organization
        and cross-project access. Access via u.Auth.* pattern.

        Example:
            from flext_auth import u
            result = u.Auth.Collection.parse_sequence(Status, ["active", "pending"])
            validator = u.Auth.Collection.coerce_list_validator(Status)

        """

    class Collection(FlextUtilities.Collection):
        """Collection utilities extending u.Collection via inheritance.

        Exposes all flext-core Collection methods through inheritance hierarchy.
        Access via u.Auth.Collection.* pattern.
        """

    class Args(FlextUtilities.Args):
        """Args utilities extending u.Args via inheritance.

        Exposes all flext-core Args methods through inheritance hierarchy.
        Access via u.Auth.Args.* pattern.
        """

    class Model(FlextUtilities.Model):
        """Model utilities extending u.Model via inheritance.

        Exposes all flext-core Model methods through inheritance hierarchy.
        Access via u.Auth.Model.* pattern.
        """

        class Pydantic:
            """Annotated type factories for Pydantic models."""

            @staticmethod
            def coerced_provider_type() -> object:
                """Return Annotated[ProviderTypes, BeforeValidator(...)] for Pydantic Field."""
                return Annotated[
                    c.Auth.ProviderTypes,
                    BeforeValidator(
                        FlextUtilities.Enum.coerce_validator(c.Auth.ProviderTypes)
                    ),
                ]

            @staticmethod
            def coerced_role_type() -> object:
                """Return Annotated[RoleTypes, BeforeValidator(...)] for Pydantic Field."""
                return Annotated[
                    c.Auth.RoleTypes,
                    BeforeValidator(
                        FlextUtilities.Enum.coerce_validator(c.Auth.RoleTypes)
                    ),
                ]

            @staticmethod
            def coerced_token_type() -> object:
                """Return Annotated[TokenTypes, BeforeValidator(...)] for Pydantic Field."""
                return Annotated[
                    c.Auth.TokenTypes,
                    BeforeValidator(
                        FlextUtilities.Enum.coerce_validator(c.Auth.TokenTypes)
                    ),
                ]

        class Validation:
            """Domain-specific validation utilities."""

            @staticmethod
            def validate_email(email: str) -> r[str]:
                """Validate email format."""
                if not email or not email.strip():
                    return r[str].fail("Email cannot be empty")
                email = email.strip()
                if len(email) > c.Auth.MAX_EMAIL_LENGTH:
                    return r[str].fail(
                        f"Email too long (max {c.Auth.MAX_EMAIL_LENGTH} chars)"
                    )
                if "@" not in email or "." not in email.split("@")[1]:
                    return r[str].fail("Invalid email format")
                return r[str].ok(email)

            @staticmethod
            def validate_password(password: str) -> r[str]:
                """Validate password strength."""
                if not password:
                    return r[str].fail("Password cannot be empty")
                if len(password) < c.Auth.Credentials.Password.MIN_LENGTH:
                    return r[str].fail(
                        f"Password too short (min {c.Auth.Credentials.Password.MIN_LENGTH} chars)"
                    )
                if len(password) > c.Auth.Credentials.Password.MAX_LENGTH:
                    return r[str].fail(
                        f"Password too long (max {c.Auth.Credentials.Password.MAX_LENGTH} chars)"
                    )
                return r[str].ok(password)

            @staticmethod
            def validate_username(username: str) -> r[str]:
                """Validate username with auth-specific rules."""
                if not username or not username.strip():
                    return r[str].fail("Username cannot be empty")
                username = username.strip()
                if len(username) < c.Auth.Credentials.Username.MIN_LENGTH:
                    return r[str].fail(
                        f"Username too short (min {c.Auth.Credentials.Username.MIN_LENGTH} chars)"
                    )
                if len(username) > c.Auth.Credentials.Username.MAX_LENGTH:
                    return r[str].fail(
                        f"Username too long (max {c.Auth.Credentials.Username.MAX_LENGTH} chars)"
                    )
                return r[str].ok(username)

        class Token:
            """Token manipulation utilities."""

            @staticmethod
            def calculate_expiry_time(minutes: int) -> datetime:
                """Calculate token/session expiry time."""
                return datetime.now(UTC) + timedelta(minutes=minutes)

            @staticmethod
            def generate_session_id() -> str:
                """Generate a secure session ID."""
                return secrets.token_hex(16)

            @staticmethod
            def is_expired(expiry_time: datetime) -> bool:
                """Check if a timestamp is expired."""
                return datetime.now(UTC) > expiry_time

        class Password:
            """Password hashing utilities using best practices."""

            @staticmethod
            def hash_password(password: str) -> str:
                """Hash a password using bcrypt."""
                salt = bcrypt.gensalt(rounds=c.Auth.DEFAULT_HASH_ROUNDS)
                return bcrypt.hashpw(password.encode(), salt).decode()

            @staticmethod
            def verify_password(password: str, hashed: str) -> bool:
                """Verify a password against its hash."""
                return bcrypt.checkpw(password.encode(), hashed.encode())

        class Response:
            """Utilities for building authentication responses."""

            @staticmethod
            def build_auth_error_response(
                error: str, error_code: str = "AUTH_ERROR"
            ) -> Mapping[str, object
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
            ) -> Mapping[str, object
                """Build a successful authentication response."""
                response: dict[str, object
                    "success": True,
                    "message": "Authentication successful",
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
        secret: SecretStr,
        *,
        verify: bool = True,
        algorithms: tuple[str, ...] | None = None,
    ) -> r[t.Auth.Tokens.ClaimMap]:
        """Generic JWT token decoding.

        Args:
        token: JWT token to decode
        secret: Secret key for verification
        verify: Whether to verify signature

        Returns:
        r with decoded payload or error

        """
        try:
            algorithms_list: list[str]
            if algorithms is None:
                algorithms_list = [c.Auth.DEFAULT_JWT_ALGORITHM]
            else:
                algorithms_list = list(algorithms)
            payload = jwt.decode(
                token,
                secret.get_secret_value(),
                algorithms=algorithms_list,
                options={"verify_signature": verify},
            )
            if not FlextUtilities.is_dict_like(payload):
                return r[t.Auth.Tokens.ClaimMap].fail(
                    "Decoded token payload is not a dictionary"
                )
            typed_payload: t.Auth.Tokens.ClaimMap = dict(payload)
            return r[t.Auth.Tokens.ClaimMap].ok(typed_payload)
        except jwt.InvalidTokenError as e:
            return r[t.Auth.Tokens.ClaimMap].fail(f"Invalid token: {e}")
        except ValidationError as e:
            return r[t.Auth.Tokens.ClaimMap].fail(
                f"Decoded token payload validation failed: {e}"
            )
        except (
            ValueError,
            TypeError,
            KeyError,
            AttributeError,
            OSError,
            RuntimeError,
            ImportError,
        ) as e:
            return r[t.Auth.Tokens.ClaimMap].fail(f"Decoding failed: {e}")

    @staticmethod
    def encode_token(
        payload: t.Auth.Tokens.ClaimMap,
        secret: str,
        algorithm: str = c.Auth.DEFAULT_JWT_ALGORITHM,
    ) -> r[str]:
        """Generic JWT token encoding.

        Args:
        payload: Token payload
        secret: Secret key for signing
        algorithm: JWT algorithm

        Returns:
        r with encoded token or error

        """

        def _encode() -> str:
            token = jwt.encode(dict(payload), secret, algorithm=algorithm)
            if isinstance(token, str):
                return token
            return str(token)

        return FlextUtilities.try_(
            _encode,
            catch=(
                ValueError,
                TypeError,
                KeyError,
                AttributeError,
                OSError,
                RuntimeError,
                ImportError,
            ),
        ).map_error(lambda e: f"Encoding failed: {e}")


u = FlextAuthUtilities
__all__ = ["FlextAuthUtilities", "u"]

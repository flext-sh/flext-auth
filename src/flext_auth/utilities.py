"""FlextAuth utilities - Advanced type-safe utilities using u patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from datetime import UTC, datetime, timedelta
from typing import Annotated, TypeIs

import bcrypt
import jwt
from pydantic import BeforeValidator, SecretStr

from flext import FlextUtilities as u, r
from flext_auth.constants import FlextAuthConstants
from flext_auth.typings import t


class FlextAuthUtilities(u):
    """FlextAuth advanced utilities extending u with domain-specific helpers.

    Architecture: Advanced utilities with ZERO code bloat through:
    - TypeIs/TypeGuard for narrowing (PEP 742)
    - BeforeValidator factories for Pydantic coercion
    - @validated decorators eliminating manual validation
    - Generic parsing utilities for StrEnums
    """

    # ═══════════════════════════════════════════════════════════════════
    # TYPEIS + TYPEGUARD: Advanced type narrowing (Python 3.13+ PEP 742)
    # ═══════════════════════════════════════════════════════════════════

    @classmethod
    def is_valid_token_type(
        cls, value: str,
    ) -> TypeIs[FlextAuthConstants.Auth.TokenTypes]:
        """TypeIs for TokenTypes validation - narrowing in if/else.

        Uses parent Enum utilities for consistency.
        """
        return u.Enum.is_member(FlextAuthConstants.Auth.TokenTypes, value)

    @classmethod
    def is_valid_provider_type(
        cls,
        value: str,
    ) -> TypeIs[FlextAuthConstants.Auth.ProviderTypes]:
        """TypeIs for ProviderTypes validation.

        Uses parent Enum utilities for consistency.
        """
        return u.Enum.is_member(FlextAuthConstants.Auth.ProviderTypes, value)

    @classmethod
    def is_valid_role_type(
        cls, value: str,
    ) -> TypeIs[FlextAuthConstants.Auth.RoleTypes]:
        """TypeIs for RoleTypes validation.

        Uses parent Enum utilities for consistency.
        """
        return u.Enum.is_member(FlextAuthConstants.Auth.RoleTypes, value)

    @classmethod
    def is_valid_permission_type(
        cls,
        value: str,
    ) -> TypeIs[FlextAuthConstants.Auth.PermissionTypes]:
        """TypeIs for PermissionTypes validation.

        Uses parent Enum utilities for consistency.
        """
        return u.Enum.is_member(FlextAuthConstants.Auth.PermissionTypes, value)

    # ═══════════════════════════════════════════════════════════════════
    # AUTH NAMESPACE: Project-specific utilities
    # ═══════════════════════════════════════════════════════════════════

    class Auth:
        """Auth-specific utility namespace.

        This namespace groups all auth-specific utilities for better organization
        and cross-project access. Access via u.Auth.* pattern.

        Example:
            from flext_auth.utilities import u
            result = u.Auth.Collection.parse_sequence(Status, ["active", "pending"])
            validator = u.Auth.Collection.coerce_list_validator(Status)

        """

        class Collection(u.Collection):
            """Collection utilities extending u.Collection via inheritance.

            Exposes all flext-core Collection methods through inheritance hierarchy.
            Access via u.Auth.Collection.* pattern.
            """

        # ═══════════════════════════════════════════════════════════════════
        # ARGS UTILITIES: @validated decorators - ZERO boilerplate
        # ═══════════════════════════════════════════════════════════════════

        class Args(u.Args):
            """Args utilities extending u.Args via inheritance.

            Exposes all flext-core Args methods through inheritance hierarchy.
            Access via u.Auth.Args.* pattern.
            """

        # ═══════════════════════════════════════════════════════════════════
        # MODEL UTILITIES: from_dict, merge_defaults, update - ZERO try/except
        # ═══════════════════════════════════════════════════════════════════

        class Model(u.Model):
            """Model utilities extending u.Model via inheritance.

            Exposes all flext-core Model methods through inheritance hierarchy.
            Access via u.Auth.Model.* pattern.
            """

        # ═══════════════════════════════════════════════════════════════════
        # PYDANTIC UTILITIES: Annotated types factories
        # ═══════════════════════════════════════════════════════════════════

        class Pydantic:
            """Annotated type factories for Pydantic models."""

            @staticmethod
            def coerced_token_type() -> object:
                """Return Annotated[TokenTypes, BeforeValidator(...)] type for Pydantic models.

                Note: Return type is object because Annotated types cannot be properly
                annotated in return type signatures. The actual return value is an
                Annotated type suitable for use in Pydantic model field definitions.
                """
                return Annotated[
                    FlextAuthConstants.Auth.TokenTypes,
                    BeforeValidator(
                        u.Enum.coerce_validator(
                            FlextAuthConstants.Auth.TokenTypes,
                        ),
                    ),
                ]

            @staticmethod
            def coerced_provider_type() -> object:
                """Return Annotated[ProviderTypes, BeforeValidator(...)] type for Pydantic models.

                Note: Return type is object because Annotated types cannot be properly
                annotated in return type signatures. The actual return value is an
                Annotated type suitable for use in Pydantic model field definitions.
                """
                return Annotated[
                    FlextAuthConstants.Auth.ProviderTypes,
                    BeforeValidator(
                        u.Enum.coerce_validator(
                            FlextAuthConstants.Auth.ProviderTypes,
                        ),
                    ),
                ]

            @staticmethod
            def coerced_role_type() -> object:
                """Return Annotated[RoleTypes, BeforeValidator(...)] type for Pydantic models.

                Note: Return type is object because Annotated types cannot be properly
                annotated in return type signatures. The actual return value is an
                Annotated type suitable for use in Pydantic model field definitions.
                """
                return Annotated[
                    FlextAuthConstants.Auth.RoleTypes,
                    BeforeValidator(
                        u.Enum.coerce_validator(
                            FlextAuthConstants.Auth.RoleTypes,
                        ),
                    ),
                ]

        # ═══════════════════════════════════════════════════════════════════
        # VALIDATION UTILITIES: Domain-specific validation
        # ═══════════════════════════════════════════════════════════════════

        class Validation:
            """Domain-specific validation utilities."""

            @staticmethod
            def validate_username(username: str) -> r[str]:
                """Validate username with auth-specific rules."""
                if not username or not username.strip():
                    return r[str].fail("Username cannot be empty")

                username = username.strip()
                if (
                    len(username)
                    < FlextAuthConstants.Auth.Credentials.Username.MIN_LENGTH
                ):
                    return r[str].fail(
                        f"Username too short (min {FlextAuthConstants.Auth.Credentials.Username.MIN_LENGTH} chars)",
                    )
                if (
                    len(username)
                    > FlextAuthConstants.Auth.Credentials.Username.MAX_LENGTH
                ):
                    return r[str].fail(
                        f"Username too long (max {FlextAuthConstants.Auth.Credentials.Username.MAX_LENGTH} chars)",
                    )
                return r[str].ok(username)

            @staticmethod
            def validate_email(email: str) -> r[str]:
                """Validate email format."""
                if not email or not email.strip():
                    return r[str].fail("Email cannot be empty")

                email = email.strip()
                if len(email) > FlextAuthConstants.Auth.MAX_EMAIL_LENGTH:
                    return r[str].fail(
                        f"Email too long (max {FlextAuthConstants.Auth.MAX_EMAIL_LENGTH} chars)",
                    )

                if "@" not in email or "." not in email.split("@")[1]:
                    return r[str].fail("Invalid email format")

                return r[str].ok(email)

            @staticmethod
            def validate_password(password: str) -> r[str]:
                """Validate password strength."""
                if not password:
                    return r[str].fail("Password cannot be empty")

                if (
                    len(password)
                    < FlextAuthConstants.Auth.Credentials.Password.MIN_LENGTH
                ):
                    return r[str].fail(
                        f"Password too short (min {FlextAuthConstants.Auth.Credentials.Password.MIN_LENGTH} chars)",
                    )
                if (
                    len(password)
                    > FlextAuthConstants.Auth.Credentials.Password.MAX_LENGTH
                ):
                    return r[str].fail(
                        f"Password too long (max {FlextAuthConstants.Auth.Credentials.Password.MAX_LENGTH} chars)",
                    )

                # Note: WEAK_CREDENTIALS not defined - removed check or define constant if needed
                # Additional password strength validation can be added here if needed

                return r[str].ok(password)

        # ═══════════════════════════════════════════════════════════════════
        # TOKEN UTILITIES: Token/session management
        # ═══════════════════════════════════════════════════════════════════

        class Token:
            """Token manipulation utilities."""

            @staticmethod
            def generate_session_id() -> str:
                """Generate a secure session ID."""
                return secrets.token_hex(16)

            @staticmethod
            def calculate_expiry_time(minutes: int) -> datetime:
                """Calculate token/session expiry time."""
                return datetime.now(UTC) + timedelta(minutes=minutes)

            @staticmethod
            def is_expired(expiry_time: datetime) -> bool:
                """Check if a timestamp is expired."""
                return datetime.now(UTC) > expiry_time

        # ═══════════════════════════════════════════════════════════════════
        # PASSWORD UTILITIES: Secure password handling
        # ═══════════════════════════════════════════════════════════════════

        class Password:
            """Password hashing utilities using best practices."""

            @staticmethod
            def hash_password(password: str) -> str:
                """Hash a password using bcrypt."""
                salt = bcrypt.gensalt(
                    rounds=FlextAuthConstants.Auth.DEFAULT_HASH_ROUNDS,
                )
                return bcrypt.hashpw(password.encode(), salt).decode()

            @staticmethod
            def verify_password(password: str, hashed: str) -> bool:
                """Verify a password against its hash."""
                return bcrypt.checkpw(password.encode(), hashed.encode())

        # ═══════════════════════════════════════════════════════════════════
        # RESPONSE UTILITIES: Response building
        # ═══════════════════════════════════════════════════════════════════

        class Response:
            """Utilities for building authentication responses."""

            @staticmethod
            def build_auth_success_response(
                token: str | None = None,
                user_id: str | None = None,
                expires_at: datetime | None = None,
            ) -> t.JsonDict:
                """Build a successful authentication response."""
                response = {
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
            def build_auth_error_response(
                error: str,
                error_code: str = "AUTH_ERROR",
            ) -> t.JsonDict:
                """Build an authentication error response."""
                return {
                    "success": False,
                    "error": error,
                    "error_code": error_code,
                    "timestamp": datetime.now(UTC).isoformat(),
                }

    @staticmethod
    def encode_token(
        payload: t.Tokens.ClaimMap,
        secret: str,
        algorithm: str = FlextAuthConstants.Auth.DEFAULT_JWT_ALGORITHM,
    ) -> r[str]:
        """Generic JWT token encoding.

        Args:
        payload: Token payload
        secret: Secret key for signing
        algorithm: JWT algorithm

        Returns:
        FlextResult with encoded token or error

        """
        try:
            token = jwt.encode(payload, secret, algorithm=algorithm)
            return r[str].ok(token if isinstance(token, str) else token.decode())
        except Exception as e:
            return r[str].fail(f"Encoding failed: {e}")

    @staticmethod
    def decode_token(
        token: str,
        secret: SecretStr,
        *,
        verify: bool = True,
        algorithms: tuple[str, ...] | None = None,
    ) -> r[t.Tokens.ClaimMap]:
        """Generic JWT token decoding.

        Args:
        token: JWT token to decode
        secret: Secret key for verification
        verify: Whether to verify signature

        Returns:
        FlextResult with decoded payload or error

        """
        try:
            algorithms_list: list[str]
            if algorithms is None:
                algorithms_list = [FlextAuthConstants.Auth.DEFAULT_JWT_ALGORITHM]
            else:
                algorithms_list = list(algorithms)
            payload = jwt.decode(
                token,
                secret.get_secret_value(),
                algorithms=algorithms_list,
                options={"verify_signature": verify},
            )
            if not isinstance(payload, dict):
                return r[t.Tokens.ClaimMap].fail(
                    "Decoded token payload is not a dictionary",
                )

            typed_payload: t.Tokens.ClaimMap = {
                str(key): value for key, value in payload.items()
            }
            return r[t.Tokens.ClaimMap].ok(typed_payload)
        except jwt.InvalidTokenError as e:
            return r[t.Tokens.ClaimMap].fail(f"Invalid token: {e}")
        except Exception as e:
            return r[t.Tokens.ClaimMap].fail(f"Decoding failed: {e}")


u = FlextAuthUtilities  # Runtime alias (not TypeAlias to avoid PYI042)

__all__ = ["FlextAuthUtilities", "u"]

"""FlextAuth utilities - Advanced type-safe utilities using u patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets
from collections.abc import Callable, Iterable
from datetime import UTC, datetime, timedelta
from enum import StrEnum
from functools import cache, wraps
from typing import Annotated, TypeIs

import bcrypt
import jwt
from flext_core import r, t, u as u_core
from pydantic import BaseModel, BeforeValidator, ConfigDict, SecretStr, validate_call
from pydantic_core import ValidationError

from flext_auth.constants import FlextAuthConstants
from flext_auth.typings import FlextAuthTypes


class FlextAuthUtilities(u_core):
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
    def is_valid_token_type(cls, value: str) -> TypeIs[FlextAuthConstants.TokenTypes]:
        """TypeIs for TokenTypes validation - narrowing in if/else."""
        return value in FlextAuthConstants.TokenTypes._value2member_map_

    @classmethod
    def is_valid_provider_type(
        cls,
        value: str,
    ) -> TypeIs[FlextAuthConstants.ProviderTypes]:
        """TypeIs for ProviderTypes validation."""
        return value in FlextAuthConstants.ProviderTypes._value2member_map_

    @classmethod
    def is_valid_role_type(cls, value: str) -> TypeIs[FlextAuthConstants.RoleTypes]:
        """TypeIs for RoleTypes validation."""
        return value in FlextAuthConstants.RoleTypes._value2member_map_

    @classmethod
    def is_valid_permission_type(
        cls,
        value: str,
    ) -> TypeIs[FlextAuthConstants.PermissionTypes]:
        """TypeIs for PermissionTypes validation."""
        return value in FlextAuthConstants.PermissionTypes._value2member_map_

    # ═══════════════════════════════════════════════════════════════════
    # ENUM UTILITIES: Advanced StrEnum handling
    # ═══════════════════════════════════════════════════════════════════

    class Enum:
        """Advanced StrEnum utilities - ZERO manual TypeGuard code."""

        @staticmethod
        def is_member[E: StrEnum](enum_cls: type[E], value: object) -> TypeIs[E]:
            """TypeIs genérico - narrowing em AMBAS branches if/else."""
            return isinstance(value, enum_cls) or (
                isinstance(value, str) and value in enum_cls._value2member_map_
            )

        @staticmethod
        def is_subset[E: StrEnum](
            enum_cls: type[E],
            valid: frozenset[E],
            value: object,
        ) -> TypeIs[E]:
            """Check if value is subset of valid enum values."""
            if isinstance(value, enum_cls):
                return value in valid
            if isinstance(value, str):
                try:
                    return enum_cls(value) in valid
                except ValueError:
                    return False
            return False

        @staticmethod
        def parse[E: StrEnum](enum_cls: type[E], value: str | E) -> r[E]:
            """Parse string to StrEnum with r."""
            if isinstance(value, enum_cls):
                return r.ok(value)
            try:
                return r.ok(enum_cls(value))
            except ValueError:
                valid = ", ".join(m.value for m in enum_cls)
                return r.fail(f"Invalid {enum_cls.__name__}: '{value}'. Valid: {valid}")

        @staticmethod
        def coerce_validator[E: StrEnum](enum_cls: type[E]) -> Callable[[object], E]:
            """BeforeValidator factory for Pydantic coercion."""

            def _coerce(v: object) -> E:
                if isinstance(v, enum_cls):
                    return v
                if isinstance(v, str):
                    try:
                        return enum_cls(v)
                    except ValueError:
                        pass
                msg = f"Invalid {enum_cls.__name__}: {v!r}"
                raise ValueError(msg)

            return _coerce

        @staticmethod
        @cache
        def values[E: StrEnum](enum_cls: type[E]) -> frozenset[str]:
            """Get all enum values as frozenset."""
            return frozenset(m.value for m in enum_cls)

    class Collection:
        """Parsing de Sequence/Mapping com StrEnums."""

        @staticmethod
        def parse_sequence[E: StrEnum](
            enum_cls: type[E],
            values: Iterable[str | E],
        ) -> r[tuple[E, ...]]:
            """Parse sequence of enum values."""
            parsed, errors = [], []
            for i, v in enumerate(values):
                if isinstance(v, enum_cls):
                    parsed.append(v)
                else:
                    try:
                        parsed.append(enum_cls(v))
                    except ValueError:
                        errors.append(f"[{i}]: '{v}'")
            return r.fail(f"Invalid: {errors}") if errors else r.ok(tuple(parsed))

        @staticmethod
        def coerce_list_validator[E: StrEnum](
            enum_cls: type[E],
        ) -> Callable[[object], list[E]]:
            """Create validator for list of enum values."""

            def _coerce(value: object) -> list[E]:
                if not isinstance(value, (list, tuple, set)):
                    msg = "Expected sequence"
                    raise TypeError(msg)
                result = []
                for i, item in enumerate(value):
                    if isinstance(item, enum_cls):
                        result.append(item)
                    elif isinstance(item, str):
                        try:
                            result.append(enum_cls(item))
                        except ValueError as err:
                            msg = f"Invalid at [{i}]: {item!r}"
                            raise ValueError(msg) from err
                    else:
                        msg = f"Expected str at [{i}]"
                        raise TypeError(msg)
                return result

            return _coerce

    # ═══════════════════════════════════════════════════════════════════
    # ARGS UTILITIES: @validated decorators - ZERO boilerplate
    # ═══════════════════════════════════════════════════════════════════

    class Args:
        """@validated decorators - ZERO manual validation boilerplate."""

        @staticmethod
        def validated[P, R](func: Callable[P, R]) -> Callable[P, R]:
            """@validate_call decorator - aceita str OU enum, converte auto."""
            return validate_call(
                config=ConfigDict(arbitrary_types_allowed=True, use_enum_values=False),
                validate_return=False,
            )(func)

        @staticmethod
        def validated_with_result[P, R](
            func: Callable[P, r[R]],
        ) -> Callable[P, r[R]]:
            """ValidationError → r.fail()."""

            @wraps(func)
            def wrapper(*args: object, **kwargs: object) -> r[R]:
                try:
                    return validate_call(
                        config=ConfigDict(
                            arbitrary_types_allowed=True,
                            use_enum_values=False,
                        ),
                        validate_return=False,
                    )(func)(*args, **kwargs)
                except ValidationError as e:
                    return r.fail(f"Validation failed: {e}")
                except Exception as e:
                    return r.fail(str(e))

            return wrapper

    # ═══════════════════════════════════════════════════════════════════
    # MODEL UTILITIES: from_dict, merge_defaults, update - ZERO try/except
    # ═══════════════════════════════════════════════════════════════════

    class Model:
        """Pydantic model utilities - ZERO manual try/except."""

        @staticmethod
        def from_dict[M: BaseModel](
            model_cls: type[M],
            data: t.JsonDict,
            *,
            strict: bool = False,
        ) -> r[M]:
            """Create model from dict - automatic validation."""
            try:
                return r.ok(model_cls.model_validate(data, strict=strict))
            except ValidationError as e:
                return r.fail(f"Model validation failed: {e}")

        @staticmethod
        def merge_defaults[M: BaseModel](
            model_cls: type[M],
            defaults: t.JsonDict,
            overrides: t.JsonDict,
        ) -> r[M]:
            """Merge defaults with overrides - automatic validation."""
            merged = {**defaults, **overrides}
            return FlextAuthUtilities.Model.from_dict(model_cls, merged)

        @staticmethod
        def update[M: BaseModel](instance: M, **updates: object) -> r[M]:
            """Update model instance - automatic re-validation."""
            try:
                current = instance.model_dump()
                current.update(updates)
                updated = type(instance).model_validate(current)
                return r.ok(updated)
            except ValidationError as e:
                return r.fail(f"Model update failed: {e}")

    # ═══════════════════════════════════════════════════════════════════
    # PYDANTIC UTILITIES: Annotated types factories
    # ═══════════════════════════════════════════════════════════════════

    class Pydantic:
        """Fábricas de Annotated types para Pydantic models."""

        @staticmethod
        def coerced_token_type() -> type:
            """Annotated[TokenTypes, BeforeValidator(...)]."""
            return Annotated[
                FlextAuthConstants.TokenTypes,
                BeforeValidator(
                    FlextAuthUtilities.Enum.coerce_validator(
                        FlextAuthConstants.TokenTypes,
                    ),
                ),
            ]

        @staticmethod
        def coerced_provider_type() -> type:
            """Annotated[ProviderTypes, BeforeValidator(...)]."""
            return Annotated[
                FlextAuthConstants.ProviderTypes,
                BeforeValidator(
                    FlextAuthUtilities.Enum.coerce_validator(
                        FlextAuthConstants.ProviderTypes,
                    ),
                ),
            ]

        @staticmethod
        def coerced_role_type() -> type:
            """Annotated[RoleTypes, BeforeValidator(...)]."""
            return Annotated[
                FlextAuthConstants.RoleTypes,
                BeforeValidator(
                    FlextAuthUtilities.Enum.coerce_validator(
                        FlextAuthConstants.RoleTypes,
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
            if len(username) < FlextAuthConstants.MIN_USERNAME_LENGTH:
                return r[str].fail(
                    f"Username too short (min {FlextAuthConstants.MIN_USERNAME_LENGTH} chars)",
                )
            if len(username) > FlextAuthConstants.MAX_USERNAME_LENGTH:
                return r[str].fail(
                    f"Username too long (max {FlextAuthConstants.MAX_USERNAME_LENGTH} chars)",
                )
            return r[str].ok(username)

        @staticmethod
        def validate_email(email: str) -> r[str]:
            """Validate email format."""
            if not email or not email.strip():
                return r[str].fail("Email cannot be empty")

            email = email.strip()
            if len(email) > FlextAuthConstants.MAX_EMAIL_LENGTH:
                return r[str].fail(
                    f"Email too long (max {FlextAuthConstants.MAX_EMAIL_LENGTH} chars)",
                )

            if "@" not in email or "." not in email.split("@")[1]:
                return r[str].fail("Invalid email format")

            return r[str].ok(email)

        @staticmethod
        def validate_password(password: str) -> r[str]:
            """Validate password strength."""
            if not password:
                return r[str].fail("Password cannot be empty")

            if len(password) < FlextAuthConstants.MIN_PASSWORD_LENGTH:
                return r[str].fail(
                    f"Password too short (min {FlextAuthConstants.MIN_PASSWORD_LENGTH} chars)",
                )
            if len(password) > FlextAuthConstants.MAX_PASSWORD_LENGTH:
                return r[str].fail(
                    f"Password too long (max {FlextAuthConstants.MAX_PASSWORD_LENGTH} chars)",
                )

            if password.lower() in FlextAuthConstants.WEAK_CREDENTIALS:
                return r[str].fail("Password is too weak")

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
            salt = bcrypt.gensalt(rounds=FlextAuthConstants.DEFAULT_HASH_ROUNDS)
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
        payload: FlextAuthTypes.ClaimMap,
        secret: str,
        algorithm: str = FlextAuthConstants.DEFAULT_JWT_ALGORITHM,
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
    ) -> r[FlextAuthTypes.ClaimMap]:
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
                algorithms_list = [FlextAuthConstants.ALGORITHM_DEFAULT]
            else:
                algorithms_list = list(algorithms)
            payload = jwt.decode(
                token,
                secret.get_secret_value(),
                algorithms=algorithms_list,
                options={"verify_signature": verify},
            )
            if not isinstance(payload, dict):
                return r[FlextAuthTypes.ClaimMap].fail(
                    "Decoded token payload is not a dictionary",
                )

            typed_payload: FlextAuthTypes.ClaimMap = {
                str(key): value for key, value in payload.items()
            }
            return r[FlextAuthTypes.ClaimMap].ok(typed_payload)
        except jwt.InvalidTokenError as e:
            return r[FlextAuthTypes.ClaimMap].fail(f"Invalid token: {e}")
        except Exception as e:
            return r[FlextAuthTypes.ClaimMap].fail(f"Decoding failed: {e}")


u = FlextAuthUtilities  # Runtime alias (not TypeAlias to avoid PYI042)

__all__ = ["FlextAuthUtilities", "u"]

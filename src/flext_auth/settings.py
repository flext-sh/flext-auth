"""FLEXT Auth Configuration - Generic Pydantic configuration with flext-core integration.

Single FlextAuthSettings class using Pydantic ConfigDict with environment variable
override support, validation, and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_core import r
from pydantic import ConfigDict, Field, SecretStr, field_validator

from flext_auth import c, m


class FlextAuthSettings(m.Value):
    """Validated settings used by auth providers and token services."""

    _global_instance: ClassVar[FlextAuthSettings | None] = None
    model_config = ConfigDict(validate_assignment=True, populate_by_name=True)

    secret_key: Annotated[
        str,
        Field(
            default="change-me-in-production-minimum-32-characters",
            alias="auth_secret",
            min_length=c.Auth.SECRET_MIN_LENGTH,
            description="Signing secret",
        ),
    ]
    algorithm: Annotated[
        str,
        Field(
            default=c.Auth.DEFAULT_JWT_ALGORITHM,
            description="JWT signing algorithm",
        ),
    ]
    issuer: Annotated[
        str, Field(default=c.Auth.DEFAULT_ISSUER, description="Token issuer")
    ]
    audience: Annotated[
        str,
        Field(
            default=c.Auth.DEFAULT_AUDIENCE,
            description="Token audience",
        ),
    ]
    expiry_minutes: Annotated[
        int,
        Field(
            default=c.Auth.DEFAULT_JWT_EXPIRY_MINUTES,
            ge=1,
            description="Access token expiry in minutes",
        ),
    ]
    session_expiry_minutes: Annotated[
        int,
        Field(
            default=c.Auth.DEFAULT_SESSION_EXPIRY_MINUTES,
            ge=1,
            description="Session expiry in minutes",
        ),
    ]
    max_sessions_per_user: Annotated[
        int,
        Field(
            default=c.Auth.DEFAULT_MAX_SESSIONS_PER_USER,
            ge=1,
            description="Max parallel sessions per user",
        ),
    ]
    hash_rounds: Annotated[
        int,
        Field(
            default=c.Auth.DEFAULT_HASH_ROUNDS,
            ge=c.Auth.HASH_ROUNDS_MIN,
            le=c.Auth.HASH_ROUNDS_MAX,
            description="Password hash rounds",
        ),
    ]

    @property
    def auth_secret(self) -> SecretStr:
        """Expose secret as SecretStr for compatibility."""
        return SecretStr(self.secret_key)

    @field_validator("secret_key", mode="before")
    @classmethod
    def _normalize_secret_key(cls, value: str | SecretStr) -> str:
        if isinstance(value, SecretStr):
            return value.get_secret_value()
        return value

    @classmethod
    def _reset_instance(cls) -> None:
        setattr(cls, "_global_instance", None)

    @classmethod
    def get_or_create_global(cls) -> r[FlextAuthSettings]:
        """Return the singleton settings instance, creating it on first access."""
        existing_instance = cls._global_instance
        if existing_instance is not None:
            return r[FlextAuthSettings].ok(existing_instance)
        created_instance = cls()
        setattr(cls, "_global_instance", created_instance)
        return r[FlextAuthSettings].ok(created_instance)


__all__ = ["FlextAuthSettings"]

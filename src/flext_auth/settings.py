"""FLEXT Auth Configuration - Generic Pydantic configuration with flext-core integration.

Single FlextAuthSettings class using Pydantic ConfigDict with environment variable
override support, validation, and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from pydantic import ConfigDict, Field, SecretStr, field_validator

from flext_auth import c, m, t
from flext_core import r


class FlextAuthSettings(m.Value):
    """Validated settings used by auth providers and token services."""

    _global_instance: ClassVar[list[FlextAuthSettings | None]] = [None]
    model_config: ClassVar[ConfigDict] = ConfigDict(
        validate_assignment=True,
        populate_by_name=True,
    )

    secret_key: Annotated[
        str,
        Field(
            alias="auth_secret",
            min_length=c.Auth.SECRET_MIN_LENGTH,
            description="Signing secret",
        ),
    ] = "change-me-in-production-minimum-32-characters"
    algorithm: Annotated[
        str,
        Field(
            description="JWT signing algorithm",
        ),
    ] = c.Auth.DEFAULT_JWT_ALGORITHM
    issuer: Annotated[
        str,
        Field(description="Token issuer"),
    ] = c.Auth.DEFAULT_ISSUER
    audience: Annotated[
        str,
        Field(
            description="Token audience",
        ),
    ] = c.Auth.DEFAULT_AUDIENCE
    expiry_minutes: Annotated[
        t.PositiveInt,
        Field(
            description="Access token expiry in minutes",
        ),
    ] = c.Auth.DEFAULT_JWT_EXPIRY_MINUTES
    session_expiry_minutes: Annotated[
        t.PositiveInt,
        Field(
            description="Session expiry in minutes",
        ),
    ] = c.Auth.DEFAULT_SESSION_EXPIRY_MINUTES
    max_sessions_per_user: Annotated[
        t.PositiveInt,
        Field(
            description="Max parallel sessions per user",
        ),
    ] = c.Auth.DEFAULT_MAX_SESSIONS_PER_USER
    hash_rounds: Annotated[
        int,
        Field(
            ge=c.Auth.HASH_ROUNDS_MIN,
            le=c.Auth.HASH_ROUNDS_MAX,
            description="Password hash rounds",
        ),
    ] = c.Auth.DEFAULT_HASH_ROUNDS

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
        cls._global_instance[0] = None

    @classmethod
    def get_or_create_global(cls) -> r[FlextAuthSettings]:
        """Return the singleton settings instance, creating it on first access."""
        existing_instance = cls._global_instance[0]
        if existing_instance is not None:
            return r[FlextAuthSettings].ok(existing_instance)
        created_instance = cls.model_validate({})
        cls._global_instance[0] = created_instance
        return r[FlextAuthSettings].ok(created_instance)


__all__ = ["FlextAuthSettings"]

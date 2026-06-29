"""FLEXT Auth Configuration - Generic Pydantic configuration with flext-core integration.

Single FlextAuthSettings class using Pydantic ConfigDict with environment variable
override support, validation, and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, ClassVar

from flext_auth import c, m, t, u
from flext_core import FlextSettingsBase


class FlextAuthSettings(FlextSettingsBase):
    """Validated settings used by auth providers and token services."""

    model_config: ClassVar[m.SettingsConfigDict] = m.SettingsConfigDict(
        env_prefix="FLEXT_AUTH_",
        extra="ignore",
        validate_assignment=True,
        populate_by_name=True,
    )

    secret_key: Annotated[
        str,
        u.Field(
            alias="auth_secret",
            min_length=c.Auth.SECRET_MIN_LENGTH,
            description="Signing secret",
        ),
    ] = u.generate_prefixed_id(prefix="auth", length=32)
    algorithm: Annotated[
        str,
        u.Field(
            description="JWT signing algorithm",
        ),
    ] = c.Auth.DEFAULT_JWT_ALGORITHM
    issuer: Annotated[
        str,
        u.Field(description="Token issuer"),
    ] = c.Auth.DEFAULT_ISSUER
    audience: Annotated[
        str,
        u.Field(
            description="Token audience",
        ),
    ] = c.Auth.DEFAULT_AUDIENCE
    expiry_minutes: Annotated[
        t.PositiveInt,
        u.Field(
            description="Access token expiry in minutes",
        ),
    ] = c.Auth.DEFAULT_JWT_EXPIRY_MINUTES
    session_expiry_minutes: Annotated[
        t.PositiveInt,
        u.Field(
            description="Session expiry in minutes",
        ),
    ] = c.Auth.DEFAULT_SESSION_EXPIRY_MINUTES
    max_sessions_per_user: Annotated[
        t.PositiveInt,
        u.Field(
            description="Max parallel sessions per user",
        ),
    ] = c.Auth.DEFAULT_MAX_SESSIONS_PER_USER
    hash_rounds: Annotated[
        int,
        u.Field(
            ge=c.Auth.HASH_ROUNDS_MIN,
            le=c.Auth.HASH_ROUNDS_MAX,
            description="Password hash rounds",
        ),
    ] = c.Auth.DEFAULT_HASH_ROUNDS

    @property
    def auth_secret(self) -> t.SecretStr:
        """Expose secret as SecretStr for compatibility."""
        return t.SecretStr(self.secret_key)

    @u.field_validator("secret_key", mode="before")
    @classmethod
    def _normalize_secret_key(cls, value: str | t.SecretStr) -> str:
        if isinstance(value, t.SecretStr):
            secret_value: str = value.get_secret_value()
            return secret_value
        return value


__all__: t.MutableSequenceOf[str] = ["FlextAuthSettings"]

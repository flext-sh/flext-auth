"""FLEXT Auth Configuration - Generic Pydantic configuration with flext-core integration.

Single FlextAuthSettings class using Pydantic ConfigDict with environment variable
override support, validation, and SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_core import FlextModels
from pydantic import Field

from flext_auth.constants import FlextAuthConstants as c


class FlextAuthSettings(FlextModels.Value):
    """Validated settings used by auth providers and token services."""

    secret_key: str = Field(
        default="change-me-in-production-minimum-32-characters",
        min_length=c.Auth.SECRET_MIN_LENGTH,
        description="Signing secret",
    )
    issuer: str = Field(default=c.Auth.DEFAULT_ISSUER, description="Token issuer")
    audience: str = Field(
        default=c.Auth.DEFAULT_AUDIENCE,
        description="Token audience",
    )
    expiry_minutes: int = Field(
        default=c.Auth.DEFAULT_JWT_EXPIRY_MINUTES,
        ge=1,
        description="Access token expiry in minutes",
    )
    session_expiry_minutes: int = Field(
        default=c.Auth.DEFAULT_SESSION_EXPIRY_MINUTES,
        ge=1,
        description="Session expiry in minutes",
    )
    max_sessions_per_user: int = Field(
        default=c.Auth.DEFAULT_MAX_SESSIONS_PER_USER,
        ge=1,
        description="Max parallel sessions per user",
    )
    hash_rounds: int = Field(
        default=c.Auth.DEFAULT_HASH_ROUNDS,
        ge=c.Auth.HASH_ROUNDS_MIN,
        le=c.Auth.HASH_ROUNDS_MAX,
        description="Password hash rounds",
    )


__all__ = ["FlextAuthSettings"]

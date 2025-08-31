"""FLEXT Auth Constants - Inheriting from flext-core foundation with centralized types.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

Following FLEXT_REFACTORING_PROMPT.md: Use FlextTypes.Core types for consistency.
"""

from __future__ import annotations

import os
import secrets
from typing import ClassVar

from flext_core import FlextConstants, FlextTypes


class FlextAuthConstants(FlextConstants):
    """Authentication constants inheriting from flext-core foundation with centralized types."""

    # =========================================================================
    # AUTHENTICATION TYPES - Using FlextTypes centralized type aliases
    # =========================================================================

    # Core authentication constants with proper FlextTypes type annotations
    DEFAULT_JWT_SECRET: ClassVar[FlextTypes.Auth.AccessToken] = os.getenv(
        "JWT_SECRET_KEY", secrets.token_urlsafe(32)
    )
    DEFAULT_ACCESS_TOKEN_MINUTES: ClassVar[int] = 30
    DEFAULT_REFRESH_TOKEN_DAYS: ClassVar[int] = 7
    DEFAULT_SESSION_TIMEOUT_HOURS: ClassVar[int] = 24

    # Password security constants with proper typing
    DEFAULT_BCRYPT_ROUNDS: ClassVar[int] = 12
    MIN_PRODUCTION_BCRYPT_ROUNDS: ClassVar[int] = 12
    MIN_PASSWORD_LENGTH: ClassVar[int] = 8
    MAX_PASSWORD_LENGTH: ClassVar[int] = 128
    MAX_LOGIN_ATTEMPTS: ClassVar[int] = 5
    DEFAULT_LOCKOUT_DURATION_MINUTES: ClassVar[int] = 30

    # Username validation with proper typing
    MIN_USERNAME_LENGTH: ClassVar[int] = 3
    MAX_USERNAME_LENGTH: ClassVar[int] = 50

    # JWT Security
    MIN_JWT_SECRET_LENGTH: ClassVar[int] = 32

    # User roles and status using FlextTypes.Auth types
    ROLE_USER: ClassVar[FlextTypes.Auth.Role] = "user"
    ROLE_ADMIN: ClassVar[FlextTypes.Auth.Role] = "REDACTED_LDAP_BIND_PASSWORD"
    ROLE_GUEST: ClassVar[FlextTypes.Auth.Role] = "guest"

    USER_STATUS_ACTIVE: ClassVar[FlextTypes.Core.String] = "active"
    USER_STATUS_INACTIVE: ClassVar[FlextTypes.Core.String] = "inactive"
    USER_STATUS_LOCKED: ClassVar[FlextTypes.Core.String] = "locked"
    USER_STATUS_SUSPENDED: ClassVar[FlextTypes.Core.String] = "suspended"

    # Token types using FlextTypes.Core.String
    TOKEN_TYPE_ACCESS: ClassVar[FlextTypes.Core.String] = "access"  # noqa: S105
    TOKEN_TYPE_REFRESH: ClassVar[FlextTypes.Core.String] = "refresh"  # noqa: S105

    # Boolean constants using FlextTypes.Core.Boolean
    SUCCESS: ClassVar[FlextTypes.Core.Boolean] = True
    FAILURE: ClassVar[FlextTypes.Core.Boolean] = False

    # Backward compatibility aliases
    DEFAULT_MAX_LOGIN_ATTEMPTS: ClassVar[int] = MAX_LOGIN_ATTEMPTS


__all__ = [
    "FlextAuthConstants",
]

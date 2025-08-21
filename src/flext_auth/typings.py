"""FLEXT Auth Typings - Centralized type definitions for the authentication system.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import datetime
from typing import TypedDict

from flext_core import TEntityId

# =============================================================================
# CORE ENTITY TYPES - Extending flext-core
# =============================================================================

type FlextAuthUserId = TEntityId
type FlextAuthSessionId = TEntityId
type FlextAuthTokenId = TEntityId

# =============================================================================
# DOMAIN TYPES - FlextAuth specific
# =============================================================================

type FlextAuthUsername = str
type FlextAuthEmail = str
type FlextAuthPassword = str
type FlextAuthRoleType = str
type FlextAuthPermissionType = str

# =============================================================================
# AUTHENTICATION DATA TYPES - Structured types
# =============================================================================

type FlextAuthResult = dict[str, object]
type FlextAuthSecurityContext = dict[str, object]
type FlextAuthLoginAttempt = dict[str, object]
type FlextAuthAuditEventType = str

# Legacy type aliases for backward compatibility (referenced in __all__)
type TEmail = FlextAuthEmail
type TPassword = FlextAuthPassword
type TSessionId = FlextAuthSessionId
type TUserId = FlextAuthUserId
type TUserRole = FlextAuthRoleType
type TUsername = FlextAuthUsername
type TAuditEventType = FlextAuthAuditEventType
type TAuthResult = FlextAuthResult
type TLoginAttempt = FlextAuthLoginAttempt
type TSecurityContext = FlextAuthSecurityContext

# =============================================================================
# USER DATA TYPES - Current API user data types
# =============================================================================


class FlextAuthUserDataType(TypedDict, total=False):
    """FlextAuth user data type definition."""

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    permissions: list[str]
    created_at: datetime
    last_login: datetime


class FlextAuthSessionDataType(TypedDict, total=False):
    """FlextAuth session data type definition."""

    id: str
    user_id: str
    token: str
    expires_at: datetime
    created_at: datetime
    is_active: bool
    ip_address: str
    user_agent: str


class FlextAuthTokenDataType(TypedDict, total=False):
    """FlextAuth token data type definition."""

    access_token: str
    refresh_token: str
    token_type: str
    expires_in: int
    scope: str


class FlextAuthHeadersType(TypedDict, total=False):
    """FlextAuth headers type definition."""

    Authorization: str
    Content_Type: str
    Accept: str


class FlextAuthClaimsType(TypedDict, total=False):
    """FlextAuth JWT claims type definition."""

    sub: str
    username: str
    email: str
    role: str
    permissions: list[str]
    is_active: bool
    iat: int
    exp: int
    iss: str
    aud: str


# =============================================================================
# CONFIGURATION TYPES - FlextAuth configuration
# =============================================================================


class FlextAuthConfigType(TypedDict, total=False):
    """FlextAuth configuration type definition."""

    app_name: str
    version: str
    debug: bool
    environment: str
    password_min_length: int
    password_max_length: int
    bcrypt_rounds: int
    max_login_attempts: int
    lockout_duration_minutes: int
    session_timeout_hours: int
    max_concurrent_sessions: int
    rate_limit_per_minute: int
    auth_rate_limit_per_minute: int
    access_token_expire_minutes: int
    refresh_token_expire_days: int
    jwt_secret_key: str


# =============================================================================
# API RESPONSE TYPES - FlextAuth API responses
# =============================================================================


class FlextAuthResponseType(TypedDict, total=False):
    """FlextAuth API response type definition."""

    success: bool
    data: object
    error: str
    message: str
    status_code: int


class FlextAuthAuthResponseType(TypedDict, total=False):
    """FlextAuth authentication response type definition."""

    authenticated: bool
    user: FlextAuthUserDataType
    tokens: FlextAuthTokenDataType
    session: FlextAuthSessionDataType


# =============================================================================
# VALIDATION TYPES - FlextAuth validation
# =============================================================================


class FlextAuthValidationResultType(TypedDict, total=False):
    """FlextAuth validation result type definition."""

    valid: bool
    errors: list[str]
    warnings: list[str]
    score: int


class FlextAuthFieldValidationType(TypedDict, total=False):
    """FlextAuth field validation type definition."""

    field: str
    value: object
    rules: list[str]
    result: FlextAuthValidationResultType


# =============================================================================
# TYPE EXPORTS - Clean type exports
# =============================================================================
type TAuthResult = FlextAuthResult
type TSecurityContext = FlextAuthSecurityContext
type TLoginAttempt = FlextAuthLoginAttempt
type TAuditEventType = FlextAuthAuditEventType

# =============================================================================
# EXPORTS - All FlextAuth types
# =============================================================================

__all__ = [
    "FlextAuthAuditEventType",
    "FlextAuthAuthResponseType",
    "FlextAuthClaimsType",
    "FlextAuthConfigType",
    "FlextAuthEmail",
    "FlextAuthFieldValidationType",
    "FlextAuthHeadersType",
    "FlextAuthLoginAttempt",
    "FlextAuthPassword",
    "FlextAuthPermissionType",
    "FlextAuthResponseType",
    "FlextAuthResult",
    "FlextAuthRoleType",
    "FlextAuthSecurityContext",
    "FlextAuthSessionDataType",
    "FlextAuthSessionId",
    "FlextAuthTokenDataType",
    "FlextAuthTokenId",
    "FlextAuthUserDataType",
    "FlextAuthUserId",
    "FlextAuthUsername",
    "FlextAuthValidationResultType",
    "TAuditEventType",
    "TAuthResult",
    "TEmail",
    "TLoginAttempt",
    "TPassword",
    "TSecurityContext",
    "TSessionId",
    "TUserId",
    "TUserRole",
    "TUsername",
]

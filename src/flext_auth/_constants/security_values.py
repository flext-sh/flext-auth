"""Authentication security and validation constants.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Set as AbstractSet
from typing import ClassVar

from flext_auth._constants import (
    FlextAuthConstantsAuthClaims,
    FlextAuthConstantsAuthEnums,
)


class FlextAuthConstantsAuthSecurityValues(FlextAuthConstantsAuthClaims):
    """Security constants for JWT, OAuth2, credentials, and rate limits."""

    # ===== JWT Constants =====
    JWT_DEFAULT_ALGORITHM: ClassVar[str] = FlextAuthConstantsAuthEnums.Algorithms.HS256
    "Default JWT algorithm."
    JWT_DEFAULT_EXPIRY_MINUTES: ClassVar[int] = 30
    "Default JWT expiry in minutes."
    JWT_MAX_EXPIRY_MINUTES: ClassVar[int] = 1440
    "Maximum JWT expiry in minutes."
    JWT_ISSUER_CLAIM: ClassVar[str] = "flext-auth"
    "Default JWT issuer claim."
    JWT_AUDIENCE_CLAIM: ClassVar[str] = "flext-users"
    "Default JWT audience claim."
    JWT_MIN_SECRET_KEY_LENGTH: ClassVar[int] = 32
    "Minimum secret key length for JWT."
    JWT_DEFAULT_TOKEN_TYPE: ClassVar[str] = (
        FlextAuthConstantsAuthEnums.AuthorizationSchemes.BEARER
    )
    "Default token type for Authorization header."

    # ===== OAuth2 Constants =====
    OAUTH2_SCOPE_DEFAULT: ClassVar[str] = "openid profile email"
    "Default OAuth2 scope."
    OAUTH2_FLOWS: ClassVar[AbstractSet[str]] = frozenset([
        "authorization_code",
        "client_credentials",
        "implicit",
    ])
    "Supported OAuth2 flows."
    OAUTH2_FLOW_DEFAULT: ClassVar[str] = "authorization_code"
    "Default OAuth2 flow."
    OAUTH2_USE_PKCE_DEFAULT: ClassVar[bool] = True
    "Whether to use PKCE by default."
    OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS: ClassVar[AbstractSet[str]] = frozenset(
        FlextAuthConstantsAuthEnums.TokenEndpointAuthMethods,
    )
    "Supported token endpoint authentication methods."
    OAUTH2_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT: ClassVar[str] = (
        FlextAuthConstantsAuthEnums.TokenEndpointAuthMethods.CLIENT_SECRET_BASIC
    )
    "Default token endpoint authentication method."

    # ===== Credentials Constants =====
    CREDENTIALS_USERNAME_MIN_LENGTH: ClassVar[int] = 3
    "Minimum username length."
    CREDENTIALS_USERNAME_MAX_LENGTH: ClassVar[int] = 50
    "Maximum username length."
    CREDENTIALS_PASSWORD_MIN_LENGTH: ClassVar[int] = 8
    "Minimum password length."
    CREDENTIALS_PASSWORD_MAX_LENGTH: ClassVar[int] = 128
    "Maximum password length."
    CREDENTIALS_PASSWORD_MIN_SCORE: ClassVar[int] = 3
    "Minimum password strength score."
    CREDENTIALS_PASSWORD_MIN_BCRYPT_HASH_LENGTH: ClassVar[int] = 60
    "Minimum bcrypt hash length."
    CREDENTIALS_PASSWORD_BCRYPT_ROUNDS: ClassVar[int] = 12
    "Default bcrypt rounds."

    # ===== Session Constants =====
    SESSION_DEFAULT_EXPIRY_MINUTES: ClassVar[int] = 120
    "Default session expiry in minutes."
    SESSION_MAX_EXPIRY_MINUTES: ClassVar[int] = 1440
    "Maximum session expiry in minutes."
    SESSION_MAX_SESSIONS_PER_USER: ClassVar[int] = 5
    "Maximum sessions per user."
    SESSION_MIN_TOKEN_LENGTH: ClassVar[int] = 32
    "Minimum session token length."

    # ===== Security Constants =====
    SECURITY_MAX_LOGIN_ATTEMPTS: ClassVar[int] = 5
    "Maximum login attempts before lockout."
    SECURITY_LOCKOUT_DURATION_MINUTES: ClassVar[int] = 15
    "Lockout duration in minutes."
    SECURITY_MAX_REQUESTS_PER_MINUTE: ClassVar[int] = 60
    "Maximum requests per minute."
    SECURITY_MAX_REQUESTS_PER_HOUR: ClassVar[int] = 1000
    "Maximum requests per hour."

    # ===== Error Codes =====
    ERROR_INVALID_CREDENTIALS: ClassVar[str] = "INVALID_CREDENTIALS"
    "Invalid credentials error code."
    ERROR_ACCOUNT_LOCKED: ClassVar[str] = "ACCOUNT_LOCKED"
    "Account locked error code."
    ERROR_ACCOUNT_DISABLED: ClassVar[str] = "ACCOUNT_DISABLED"
    "Account disabled error code."

    # ===== Validation Constants =====
    VALIDATION_SHORT_NAME_MAX: ClassVar[int] = 64
    "Maximum length for short names (provider keys, capabilities)."

    # ===== Model Validation Constants =====
    VALIDATION_BCRYPT_ROUNDS: ClassVar[int] = 12
    "Bcrypt rounds for password hashing."
    VALIDATION_DEFAULT_TOKEN_EXPIRY_MINUTES: ClassVar[int] = 60
    "Default token expiry in minutes."
    VALIDATION_MAX_ROLE_NAME_LENGTH: ClassVar[int] = 50
    "Maximum length for role names."
    VALIDATION_MAX_ROLE_DESCRIPTION_LENGTH: ClassVar[int] = 500
    "Maximum length for role descriptions."
    VALIDATION_MAX_PERMISSION_NAME_LENGTH: ClassVar[int] = 100
    "Maximum length for permission names."
    VALIDATION_MAX_PERMISSION_DESCRIPTION_LENGTH: ClassVar[int] = 500
    "Maximum length for permission descriptions."


__all__: list[str] = ["FlextAuthConstantsAuthSecurityValues"]

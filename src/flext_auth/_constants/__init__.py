# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Constants package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import defer_lazy_bases, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._constants.auth import FlextAuthConstantsAuth
    from flext_auth._constants.auth_claims import FlextAuthConstantsAuthClaims
    from flext_auth._constants.auth_enums import FlextAuthConstantsAuthEnums
    from flext_auth._constants.auth_security import FlextAuthConstantsAuthSecurity
    from flext_auth._constants.auth_values import FlextAuthConstantsAuthValues
    from flext_auth._constants.base import FlextAuthConstantsBase
    from flext_auth._constants.security_values import (
        FlextAuthConstantsAuthSecurityValues,
    )


__all__: tuple[str, ...] = (
    "FlextAuthConstantsAuth",
    "FlextAuthConstantsAuthClaims",
    "FlextAuthConstantsAuthEnums",
    "FlextAuthConstantsAuthSecurity",
    "FlextAuthConstantsAuthSecurityValues",
    "FlextAuthConstantsAuthValues",
    "FlextAuthConstantsBase",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextAuthConstantsAuth": ".auth",
        "FlextAuthConstantsAuthClaims": ".auth_claims",
        "FlextAuthConstantsAuthEnums": ".auth_enums",
        "FlextAuthConstantsAuthSecurity": ".auth_security",
        "FlextAuthConstantsAuthSecurityValues": ".security_values",
        "FlextAuthConstantsAuthValues": ".auth_values",
        "FlextAuthConstantsBase": ".base",
    },
    public_exports=__all__,
    deferred_members={
        "FlextAuthConstantsAuth": (),
        "FlextAuthConstantsAuthClaims": (
            "PATTERN_EMAIL",
            "PATTERN_IDENTIFIER_LOWERCASE",
            "VALID_TOKEN_TYPES",
            "VALID_PROVIDER_TYPES",
            "VALID_ROLE_TYPES",
            "VALID_PERMISSION_TYPES",
            "KEY_SUBJECT",
            "KEY_IDENTITY_ID",
            "KEY_USER_ID",
            "KEY_USERNAME",
            "KEY_NAME",
            "KEY_PREFERRED_USERNAME",
            "KEY_CONTACT",
            "KEY_EMAIL",
            "KEY_ROLES",
            "KEY_SCOPE",
            "KEY_CONTACT_DOMAIN",
            "TOKEN_IDENTITY_KEYS",
            "TOKEN_NAME_KEYS",
            "TOKEN_CONTACT_KEYS",
            "TOKEN_IDENTITY_PASSTHROUGH_FIELDS",
            "DEFAULT_OAUTH_CONTACT_DOMAIN",
            "DEFAULT_KERBEROS_CONTACT_DOMAIN",
            "DEFAULT_KERBEROS_USERNAME",
            "SCOPE_SEPARATOR",
            "DEFAULT_TIMEOUT",
            "DEFAULT_MAX_RETRIES",
            "DEFAULT_JWT_EXPIRY_MINUTES",
            "DEFAULT_SESSION_EXPIRY_MINUTES",
            "DEFAULT_MAX_SESSIONS_PER_USER",
            "DEFAULT_HASH_ROUNDS",
            "DEFAULT_JWT_ALGORITHM",
            "MAX_USERNAME_LENGTH",
            "MAX_EMAIL_LENGTH",
            "MIN_PASSWORD_LENGTH",
            "MAX_PASSWORD_LENGTH",
            "MAX_TOKEN_LENGTH",
            "MAX_SECRET_KEY_LENGTH",
            "DEFAULT_ISSUER",
            "DEFAULT_AUDIENCE",
            "HASH_ROUNDS_MIN",
            "HASH_ROUNDS_MAX",
            "CREDENTIAL_MIN_LENGTH",
            "CREDENTIAL_MAX_LENGTH",
            "MAX_ATTEMPTS_DEFAULT",
            "LOCKOUT_DURATION_MINUTES",
            "VALIDATION_LIMITS",
            "SUCCESS_AUTH_RESPONSE",
        ),
        "FlextAuthConstantsAuthEnums": (
            "DEFAULT_ADMIN_USERNAME",
            "DEFAULT_ADMIN_EMAIL",
            "DEFAULT_ADMIN_CREDENTIAL",
            "DEFAULT_ADMIN_ROLES",
            "TokenTypes",
            "ProviderTypes",
            "RoleTypes",
            "PermissionTypes",
            "Algorithms",
            "AuthorizationSchemes",
            "TokenEndpointAuthMethods",
            "IntrospectionTokenTypeHints",
        ),
        "FlextAuthConstantsAuthSecurityValues": (
            "JWT_DEFAULT_ALGORITHM",
            "JWT_DEFAULT_EXPIRY_MINUTES",
            "JWT_MAX_EXPIRY_MINUTES",
            "JWT_ISSUER_CLAIM",
            "JWT_AUDIENCE_CLAIM",
            "JWT_MIN_SECRET_KEY_LENGTH",
            "JWT_DEFAULT_TOKEN_TYPE",
            "OAUTH2_SCOPE_DEFAULT",
            "OAUTH2_FLOWS",
            "OAUTH2_FLOW_DEFAULT",
            "OAUTH2_USE_PKCE_DEFAULT",
            "OAUTH2_TOKEN_ENDPOINT_AUTH_METHODS",
            "OAUTH2_TOKEN_ENDPOINT_AUTH_METHOD_DEFAULT",
            "CREDENTIALS_USERNAME_MIN_LENGTH",
            "CREDENTIALS_USERNAME_MAX_LENGTH",
            "CREDENTIALS_PASSWORD_MIN_LENGTH",
            "CREDENTIALS_PASSWORD_MAX_LENGTH",
            "CREDENTIALS_PASSWORD_MIN_SCORE",
            "CREDENTIALS_PASSWORD_MIN_BCRYPT_HASH_LENGTH",
            "CREDENTIALS_PASSWORD_BCRYPT_ROUNDS",
            "SESSION_DEFAULT_EXPIRY_MINUTES",
            "SESSION_MAX_EXPIRY_MINUTES",
            "SESSION_MAX_SESSIONS_PER_USER",
            "SESSION_MIN_TOKEN_LENGTH",
            "SECURITY_MAX_LOGIN_ATTEMPTS",
            "SECURITY_LOCKOUT_DURATION_MINUTES",
            "SECURITY_MAX_REQUESTS_PER_MINUTE",
            "SECURITY_MAX_REQUESTS_PER_HOUR",
            "ERROR_INVALID_CREDENTIALS",
            "ERROR_ACCOUNT_LOCKED",
            "ERROR_ACCOUNT_DISABLED",
            "VALIDATION_SHORT_NAME_MAX",
            "VALIDATION_BCRYPT_ROUNDS",
            "VALIDATION_DEFAULT_TOKEN_EXPIRY_MINUTES",
            "VALIDATION_MAX_ROLE_NAME_LENGTH",
            "VALIDATION_MAX_ROLE_DESCRIPTION_LENGTH",
            "VALIDATION_MAX_PERMISSION_NAME_LENGTH",
            "VALIDATION_MAX_PERMISSION_DESCRIPTION_LENGTH",
        ),
        "FlextAuthConstantsAuthSecurity": (),
        "FlextAuthConstantsAuthValues": (
            "REGISTRY_PROVIDERS_CATEGORY",
            "REGISTRY_CONFIG_CATEGORY",
            "REGISTRY_METADATA_CATEGORY",
            "PROVIDER_VERSION",
        ),
        "FlextAuthConstantsBase": ("SECRET_MIN_LENGTH",),
    },
)

defer_lazy_bases(
    __name__,
    {
        "FlextAuthConstantsAuth": ((".", "FlextAuthConstantsAuthValues"),),
        "FlextAuthConstantsAuthClaims": ((".", "FlextAuthConstantsAuthEnums"),),
        "FlextAuthConstantsAuthSecurity": (
            (".", "FlextAuthConstantsAuthClaims"),
            (".", "FlextAuthConstantsAuthSecurityValues"),
        ),
        "FlextAuthConstantsAuthValues": ((".", "FlextAuthConstantsAuthSecurity"),),
    },
)

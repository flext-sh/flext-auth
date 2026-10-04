"""Authentication enum constants.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from enum import StrEnum, auto, unique
from typing import ClassVar


class FlextAuthConstantsAuthEnums:
    DEFAULT_ADMIN_USERNAME: ClassVar[str] = "admin"
    DEFAULT_ADMIN_EMAIL: ClassVar[str] = "admin@example.com"

    @unique
    class TokenTypes(StrEnum):
        """Token type enumeration - automatic Pydantic validation.

        PYDANTIC MODELS:
            model_config: ClassVar[t.ConfigDict] = ConfigDict(use_enum_values=True)
            token_type: FlextAuthConstants.Auth.TokenTypes

        Result:
            - Accepts "access", "refresh", etc. or TokenTypes.ACCESS
            - Serializes as string
            - Automatically validates (rejects invalid values)

        DRY Pattern:
            StrEnum is the single source of truth. Use TokenTypes.ACCESS.value
            or TokenTypes.ACCESS directly - no base strings needed.
        """

        ACCESS = "access"
        REFRESH = "refresh"
        API = "api"
        BEARER = "bearer"

    @unique
    class ProviderTypes(StrEnum):
        """Provider type enumeration - automatic Pydantic validation.

        DRY Pattern:
            StrEnum is the single source of truth. Use ProviderTypes.JWT.value
            or ProviderTypes.JWT directly - no base strings needed.
        """

        BASIC = "basic"
        JWT = "jwt"
        OAUTH2 = "oauth2"
        SAML = "saml"
        LDAP = "ldap"
        CERTIFICATE = "certificate"
        KERBEROS = "kerberos"
        APIKEY = "apikey"

    @unique
    class RoleTypes(StrEnum):
        """Role type enumeration - automatic Pydantic validation.

        DRY Pattern:
            StrEnum is the single source of truth. Use RoleTypes.ADMIN.value
            or RoleTypes.ADMIN directly - no base strings needed.
        """

        ADMIN = "admin"
        USER = "user"
        MODERATOR = "moderator"
        GUEST = "guest"

    @unique
    class PermissionTypes(StrEnum):
        """Permission type enumeration - automatic Pydantic validation.

        DRY Pattern:
            StrEnum is the single source of truth. Use PermissionTypes.READ.value
            or PermissionTypes.READ directly - no base strings needed.
        """

        READ = "read"
        WRITE = "write"
        DELETE = "delete"
        ADMIN = "admin"

    @unique
    class Algorithms(StrEnum):
        """Algorithm type enumeration.

        DRY Pattern:
            StrEnum is the single source of truth. Use Algorithms.HS256.value
            or Algorithms.HS256 directly - no base strings needed.
        """

        HS256 = "HS256"
        RS256 = "RS256"
        ES256 = "ES256"

    @unique
    class AuthorizationSchemes(StrEnum):
        """HTTP Authorization header schemes (RFC 6750)."""

        BEARER = "Bearer"

    @unique
    class TokenEndpointAuthMethods(StrEnum):
        """OAuth2 token endpoint client authentication methods (RFC 7591)."""

        CLIENT_SECRET_BASIC = auto()
        CLIENT_SECRET_POST = auto()
        NONE = auto()


__all__: list[str] = ["FlextAuthConstantsAuthEnums"]

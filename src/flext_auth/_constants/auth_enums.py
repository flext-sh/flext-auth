"""Authentication enum constants."""

from __future__ import annotations

from enum import StrEnum, unique
from typing import ClassVar


class FlextAuthConstantsAuthEnums:
    DEFAULT_ADMIN_USERNAME: ClassVar[str] = "admin"
    DEFAULT_ADMIN_EMAIL: ClassVar[str] = "admin@example.com"

    @unique
    class TokenTypes(StrEnum):
        """Token type enumeration - automatic Pydantic validation.

        PYDANTIC MODELS:
            model_config: ClassVar[p.ConfigDict] = ConfigDict(use_enum_values=True)
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

        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
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
        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"

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


__all__: list[str] = ["FlextAuthConstantsAuthEnums"]

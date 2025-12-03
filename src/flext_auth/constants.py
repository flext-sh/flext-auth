"""FlextAuth constants - Advanced type-safe constants using StrEnum + Pydantic 2 patterns.

FLEXT-AUTH domain constants with FlextCore integration. Uses advanced Python 3.13+ features:
- StrEnum for type-safe enumerations with Pydantic 2 validation
- PEP 695 type aliases for strict Literal types
- Nested classes for logical grouping (TokenTypes, ProviderTypes, etc.)
- TypeIs and TypeGuard for advanced type narrowing
- Collections.abc for immutable validation sets

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Callable, Mapping, Set as AbstractSet
from enum import StrEnum
from types import MappingProxyType
from typing import Final, Literal, TypeGuard, TypeIs

from flext_core import FlextConstants, FlextResult, u

# ═══════════════════════════════════════════════════════════════════════════
# STRENUM + PYDANTIC 2: PADRÃO DEFINITIVO PARA FLEXT-AUTH
# ═══════════════════════════════════════════════════════════════════════════

# PRINCÍPIO FUNDAMENTAL: StrEnum + Pydantic 2 = Validação Automática!
# - NÃO precisa criar Literal separado para validação
# - NÃO precisa criar frozenset para validação
# - NÃO precisa criar AfterValidator
# - Pydantic valida automaticamente contra o StrEnum

# SUBSETS: Use Literal[TokenTypes.ACCESS, TokenTypes.REFRESH] para aceitar apenas ALGUNS valores.
# Isso referencia o enum member, não duplica strings!


class FlextAuthConstants(FlextConstants):
    """FlextAuth domain constants extending FlextConstants.

    Architecture: Layer 1 (Domain Constants - Extends Core)
    =========================================================
    Provides domain-specific constants for authentication using advanced patterns:
    - StrEnum for type-safe enumerations with automatic Pydantic validation
    - PEP 695 type aliases for strict Literal unions
    - Nested classes for logical grouping (TokenTypes, ProviderTypes, etc.)
    - TypeIs/TypeGuard methods for advanced type narrowing
    - Collections.abc for immutable validation sets

    Integration with p:
    This class provides the constant registry that FlextAuthProtocols depend on.
    Structural typing ensures protocol compliance without explicit inheritance.

    Usage Patterns:
        # Direct access (recommended)
        >>> from flext_auth.constants import FlextAuthConstants as AuthConst
        >>> token_type = AuthConst.TokenTypes.ACCESS
        >>> provider = AuthConst.ProviderTypes.JWT

        # Type-safe validation
        >>> AuthConst.TokenTypes.is_valid_token_type("access")  # True
        >>> AuthConst.ProviderTypes.is_jwt_provider("jwt")  # True

        # Literal types for Pydantic models
        >>> token: AuthConst.TokenTypeLiteral  # Type-safe: "access" | "refresh" | ...
    """

    # ═══════════════════════════════════════════════════════════════════
    # STRENUM: Única declaração necessária para validação automática
    # ═══════════════════════════════════════════════════════════════════

    class TokenTypes(StrEnum):
        """Token type enumeration - automatic Pydantic validation.

        PYDANTIC MODELS:
            model_config = ConfigDict(use_enum_values=True)
            token_type: FlextAuthConstants.TokenTypes

        Resultado:
            - Aceita "access", "refresh", etc. ou TokenTypes.ACCESS
            - Serializa como string
            - Valida automaticamente (rejeita valores inválidos)
        """

        ACCESS = "access"
        REFRESH = "refresh"
        API = "api"
        BEARER = "bearer"

    class ProviderTypes(StrEnum):
        """Provider type enumeration - automatic Pydantic validation."""

        BASIC = "basic"
        JWT = "jwt"
        OAUTH2 = "oauth2"
        SAML = "saml"
        LDAP = "ldap"
        CERTIFICATE = "certificate"
        KERBEROS = "kerberos"
        APIKEY = "apikey"

    class RoleTypes(StrEnum):
        """Role type enumeration - automatic Pydantic validation."""

        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"
        USER = "user"
        MODERATOR = "moderator"
        GUEST = "guest"

    class PermissionTypes(StrEnum):
        """Permission type enumeration - automatic Pydantic validation."""

        READ = "read"
        WRITE = "write"
        DELETE = "delete"
        ADMIN = "REDACTED_LDAP_BIND_PASSWORD"

    class Algorithms(StrEnum):
        """Algorithm type enumeration."""

        HS256 = "HS256"
        RS256 = "RS256"
        ES256 = "ES256"

    # ═══════════════════════════════════════════════════════════════════
    # SUBSETS: Literal referenciando membros do StrEnum
    # ═══════════════════════════════════════════════════════════════════
    # Use para aceitar apenas ALGUNS valores do enum em métodos
    # Isso NÃO duplica strings - referencia o enum member!

    type AccessTokens = Literal[TokenTypes.ACCESS, TokenTypes.BEARER]
    """Access token types for operations."""
    type RefreshTokens = Literal[TokenTypes.REFRESH]
    """Refresh token types."""
    type BearerTokens = Literal[TokenTypes.BEARER, TokenTypes.ACCESS]
    """Bearer token types."""
    type AdminRoles = Literal[RoleTypes.ADMIN]
    """Admin role types."""
    type UserRoles = Literal[RoleTypes.USER, RoleTypes.MODERATOR, RoleTypes.GUEST]
    """User role types."""
    type WritePermissions = Literal[PermissionTypes.WRITE, PermissionTypes.DELETE]
    """Write permission types."""
    type AdminPermissions = Literal[PermissionTypes.ADMIN]
    """Admin permission types."""

    # ═══════════════════════════════════════════════════════════════════
    # TYPEIS + TYPEGUARD: Advanced type narrowing (Python 3.13+ PEP 742)
    # ═══════════════════════════════════════════════════════════════════

    @classmethod
    def is_valid_token_type(cls, value: str) -> TypeIs[TokenTypes]:
        """TypeIs for TokenTypes validation - narrowing in if/else."""
        return value in cls.TokenTypes._value2member_map_

    @classmethod
    def is_access_token(cls, value: str) -> TypeGuard[AccessTokens]:
        """TypeGuard for access token subset."""
        return value in {cls.TokenTypes.ACCESS.value, cls.TokenTypes.BEARER.value}

    @classmethod
    def is_refresh_token(cls, value: str) -> TypeGuard[RefreshTokens]:
        """TypeGuard for refresh token subset."""
        return value == cls.TokenTypes.REFRESH.value

    @classmethod
    def is_valid_provider_type(cls, value: str) -> TypeIs[ProviderTypes]:
        """TypeIs for ProviderTypes validation."""
        return value in cls.ProviderTypes._value2member_map_

    @classmethod
    def is_jwt_provider(cls, value: str) -> TypeGuard[Literal[ProviderTypes.JWT]]:
        """TypeGuard for JWT provider."""
        return value == cls.ProviderTypes.JWT.value

    @classmethod
    def is_oauth2_provider(cls, value: str) -> TypeGuard[Literal[ProviderTypes.OAUTH2]]:
        """TypeGuard for OAuth2 provider."""
        return value == cls.ProviderTypes.OAUTH2.value

    @classmethod
    def is_valid_role_type(cls, value: str) -> TypeIs[RoleTypes]:
        """TypeIs for RoleTypes validation."""
        return value in cls.RoleTypes._value2member_map_

    @classmethod
    def is_REDACTED_LDAP_BIND_PASSWORD_role(cls, value: str) -> TypeGuard[AdminRoles]:
        """TypeGuard for REDACTED_LDAP_BIND_PASSWORD role subset."""
        return value == cls.RoleTypes.ADMIN.value

    @classmethod
    def is_user_role(cls, value: str) -> TypeGuard[UserRoles]:
        """TypeGuard for user role subset."""
        return value in {
            cls.RoleTypes.USER.value,
            cls.RoleTypes.MODERATOR.value,
            cls.RoleTypes.GUEST.value,
        }

    @classmethod
    def is_valid_permission_type(cls, value: str) -> TypeIs[PermissionTypes]:
        """TypeIs for PermissionTypes validation."""
        return value in cls.PermissionTypes._value2member_map_

    @classmethod
    def is_write_permission(cls, value: str) -> TypeGuard[WritePermissions]:
        """TypeGuard for write permission subset."""
        return value in {
            cls.PermissionTypes.WRITE.value,
            cls.PermissionTypes.DELETE.value,
        }

    @classmethod
    def is_REDACTED_LDAP_BIND_PASSWORD_permission(cls, value: str) -> TypeGuard[AdminPermissions]:
        """TypeGuard for REDACTED_LDAP_BIND_PASSWORD permission subset."""
        return value == cls.PermissionTypes.ADMIN.value

    # ═══════════════════════════════════════════════════════════════════
    # IMMUTABLE COLLECTIONS: frozenset para O(1) validação
    # ═══════════════════════════════════════════════════════════════════

    VALID_TOKEN_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value for member in TokenTypes.__members__.values()
    )
    """Immutable set of all valid token types for O(1) validation."""

    VALID_PROVIDER_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value for member in ProviderTypes.__members__.values()
    )
    """Immutable set of all valid provider types."""

    VALID_ROLE_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value for member in RoleTypes.__members__.values()
    )
    """Immutable set of all valid role types."""

    VALID_PERMISSION_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value for member in PermissionTypes.__members__.values()
    )
    """Immutable set of all valid permission types."""

    ACCESS_TOKEN_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value for member in [TokenTypes.ACCESS, TokenTypes.BEARER]
    )
    """Access token types for validation."""

    USER_ROLE_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value
        for member in [RoleTypes.USER, RoleTypes.MODERATOR, RoleTypes.GUEST]
    )
    """User role types for validation."""

    WRITE_PERMISSION_TYPES: Final[AbstractSet[str]] = frozenset(
        member.value for member in [PermissionTypes.WRITE, PermissionTypes.DELETE]
    )
    """Write permission types for validation."""

    # ═══════════════════════════════════════════════════════════════════
    # CONFIGURATION CONSTANTS: Valores padrão e limites
    # ═══════════════════════════════════════════════════════════════════

    DEFAULT_TIMEOUT: Final[float] = 30.0
    """Default request timeout in seconds."""

    DEFAULT_MAX_RETRIES: Final[int] = 3
    """Default maximum retry attempts."""

    DEFAULT_JWT_EXPIRY_MINUTES: Final[int] = 1440  # 24 hours
    """Default JWT token expiry in minutes."""

    DEFAULT_SESSION_EXPIRY_MINUTES: Final[int] = 1440  # 24 hours
    """Default session expiry in minutes."""

    DEFAULT_MAX_SESSIONS_PER_USER: Final[int] = 5
    """Default maximum sessions per user."""

    DEFAULT_HASH_ROUNDS: Final[int] = 12
    """Default bcrypt hash rounds."""

    DEFAULT_JWT_ALGORITHM: Final[str] = "HS256"
    """Default JWT algorithm."""

    MAX_USERNAME_LENGTH: Final[int] = 255
    """Maximum username length."""

    MAX_EMAIL_LENGTH: Final[int] = 254
    """Maximum email length."""

    MIN_PASSWORD_LENGTH: Final[int] = 8
    """Minimum password length."""

    MAX_PASSWORD_LENGTH: Final[int] = 128
    """Maximum password length."""

    MAX_TOKEN_LENGTH: Final[int] = 4096
    """Maximum token length."""

    MAX_SECRET_KEY_LENGTH: Final[int] = 4096
    """Maximum secret key length."""

    # ═══════════════════════════════════════════════════════════════════
    # VALIDATION LIMITS: Mappings imutáveis para validação
    # ═══════════════════════════════════════════════════════════════════

    VALIDATION_LIMITS: Final[Mapping[str, int | float]] = MappingProxyType({
        "MAX_USERNAME_LENGTH": MAX_USERNAME_LENGTH,
        "MAX_EMAIL_LENGTH": MAX_EMAIL_LENGTH,
        "MIN_PASSWORD_LENGTH": MIN_PASSWORD_LENGTH,
        "MAX_PASSWORD_LENGTH": MAX_PASSWORD_LENGTH,
        "MAX_TOKEN_LENGTH": MAX_TOKEN_LENGTH,
        "MAX_SECRET_KEY_LENGTH": MAX_SECRET_KEY_LENGTH,
        "DEFAULT_TIMEOUT": DEFAULT_TIMEOUT,
    })
    """Validation limits mapping."""

    # ═══════════════════════════════════════════════════════════════════
    # RESPONSE TEMPLATES: Mappings imutáveis
    # ═══════════════════════════════════════════════════════════════════

    SUCCESS_AUTH_RESPONSE: Final[Mapping[str, str | None]] = MappingProxyType({
        "status": "success",
        "message": "Authentication successful",
        "token_type": None,
    })
    """Template for successful authentication responses."""

    ERROR_AUTH_RESPONSE: Final[Mapping[str, str | None]] = MappingProxyType({
        "status": "error",
        "message": None,
        "error_code": None,
    })
    """Template for authentication error responses."""

    # ═══════════════════════════════════════════════════════════════════
    # UTILITY METHODS: Validação avançada com u
    # ═══════════════════════════════════════════════════════════════════

    @classmethod
    def validate_token_type_with_result(cls, value: str) -> FlextResult[TokenTypes]:
        """Validate token type using u.Enum.parse."""
        return u.Enum.parse(cls.TokenTypes, value)

    @classmethod
    def validate_provider_type_with_result(
        cls, value: str
    ) -> FlextResult[ProviderTypes]:
        """Validate provider type using u.Enum.parse."""
        return u.Enum.parse(cls.ProviderTypes, value)

    @classmethod
    def validate_role_type_with_result(cls, value: str) -> FlextResult[RoleTypes]:
        """Validate role type using u.Enum.parse."""
        return u.Enum.parse(cls.RoleTypes, value)

    @classmethod
    def validate_permission_type_with_result(
        cls, value: str
    ) -> FlextResult[PermissionTypes]:
        """Validate permission type using u.Enum.parse."""
        return u.Enum.parse(cls.PermissionTypes, value)

    @classmethod
    def create_token_type_validator(cls) -> Callable[[str], TokenTypes]:
        """Create BeforeValidator for TokenTypes in Pydantic models."""
        return uvalidator(cls.TokenTypes)

    @classmethod
    def create_provider_type_validator(cls) -> Callable[[str], ProviderTypes]:
        """Create BeforeValidator for ProviderTypes in Pydantic models."""
        return uvalidator(cls.ProviderTypes)

    # ═══════════════════════════════════════════════════════════════════
    # LITERAL TYPES: PEP 695 strict type aliases (Python 3.13+)
    # ═══════════════════════════════════════════════════════════════════

    type TokenTypeLiteral = Literal["access", "refresh", "api", "bearer"]
    """Token type literal - matches TokenTypes StrEnum values exactly."""

    type ProviderTypeLiteral = Literal[
        "basic", "jwt", "oauth2", "saml", "ldap", "certificate", "kerberos", "apikey"
    ]
    """Provider type literal - matches ProviderTypes StrEnum values exactly."""

    type RoleTypeLiteral = Literal["REDACTED_LDAP_BIND_PASSWORD", "user", "moderator", "guest"]
    """Role type literal - matches RoleTypes StrEnum values exactly."""

    type PermissionTypeLiteral = Literal["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]
    """Permission type literal - matches PermissionTypes StrEnum values exactly."""

    type AlgorithmLiteral = Literal["HS256", "RS256", "ES256"]
    """Algorithm literal - matches Algorithms StrEnum values exactly."""

    # ═══════════════════════════════════════════════════════════════════
    # REFERÊNCIAS A FLEXT-CORE: Explicit references (não aliases)
    # ═══════════════════════════════════════════════════════════════════

    class Inherited:
        """Explicit references to inherited constants from FlextConstants.

        Use for documenting which constants from FlextConstants are used
        in this domain, without creating aliases.
        """

        # Apenas referências, não aliases
        # Use FlextConstants.Cqrs.Status diretamente no código


__all__ = ["FlextAuthConstants"]

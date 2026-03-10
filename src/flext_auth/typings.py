"""FLEXT Auth Types - Type definitions and aliases.

Uses Pydantic models from flext_auth for consolidated type definitions.
Maintains backward compatibility where possible while enforcing new patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, Literal, override

from flext_api import FlextApiTypes
from pydantic import BeforeValidator, Field, SecretStr

from flext_auth import c, m


class FlextAuthTypes(FlextApiTypes):
    """Authentication-specific type definitions extending t with composition."""

    ProviderConfig = m.Auth.ProviderConfig

    class Auth:
        """Authentication-related type definitions."""

        type AuthMethod = Literal["basic", "jwt", "oauth2", "apikey"]
        type AuthStatus = Literal[
            "authenticated", "unauthenticated", "expired", "invalid"
        ]
        type CoercedTokenTypes = Annotated[
            c.Auth.TokenTypes, BeforeValidator(lambda x: x)
        ]
        type CoercedProviderTypes = Annotated[
            c.Auth.ProviderTypes, BeforeValidator(lambda x: x)
        ]
        type CoercedRoleTypes = Annotated[
            c.Auth.RoleTypes, BeforeValidator(lambda x: x)
        ]

        # Model references from m.Auth
        OAuth2TokenResponse = m.Auth.OAuth2TokenResponse
        KerberosTicketData = m.Auth.KerberosTicketData
        HttpResponseData = m.Auth.HttpResponseData

        class UserManagement:
            """User management type definitions."""

            type UserStatus = Literal["active", "inactive", "locked", "pending"]
            type UserAction = Literal[
                "create", "update", "delete", "activate", "deactivate"
            ]

        class SessionManagement:
            """Session management type definitions."""

            type SessionStatus = Literal["active", "expired", "revoked"]
            type SessionAction = Literal["create", "extend", "revoke", "validate"]

        class TokenManagement:
            """Token management type definitions."""

            type TokenType = Literal["access", "refresh", "api", "bearer"]
            type TokenStatus = Literal["valid", "expired", "revoked", "invalid"]

        class Authorization:
            """Authorization type definitions."""

            type Permission = Literal[
                "read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"
            ]
            type Role = Literal[
                "user", "moderator", "REDACTED_LDAP_BIND_PASSWORD", "guest"
            ]

        class Security:
            """Security-related type definitions."""

            type SecurityEvent = Literal[
                "login_success", "login_failure", "token_created", "token_revoked"
            ]
            type ThreatLevel = Literal["low", "medium", "high", "critical"]

        class Project:
            """Project type namespace."""

            type ProjectType = Literal["flext-auth", "flext-core", "flext-api"]

        class Providers:
            """Provider-oriented type definitions."""

            # Model reference from m.Auth.Providers
            Metadata = m.Auth.Providers.Metadata

            type Key = Annotated[
                str,
                Field(
                    min_length=1,
                    max_length=c.Auth.Validation.SHORT_NAME_MAX,
                    pattern="^[a-z0-9](?:[a-z0-9\\-_.]{0,62}[a-z0-9])?$",
                    description="Provider registry key",
                ),
            ]
            type Capability = Annotated[
                str,
                Field(
                    min_length=1,
                    max_length=c.Auth.Validation.SHORT_NAME_MAX,
                    pattern="^[a-z][a-z0-9_:-]*$",
                    description="Provider capability identifier",
                ),
            ]
            type CapabilitySet = Annotated[
                frozenset[Capability],
                Field(min_length=1, description="Declared capabilities"),
            ]

        class Credentials:
            """Credential payload type definitions."""

            type Username = Annotated[
                str,
                Field(
                    min_length=1,
                    max_length=c.Auth.Validation.LONG_NAME_MAX,
                    description="Identity username",
                ),
            ]
            type Password = Annotated[
                str,
                Field(
                    min_length=c.Auth.CREDENTIAL_MIN_LENGTH,
                    max_length=c.Auth.CREDENTIAL_MAX_LENGTH,
                    description="Raw credential string",
                ),
            ]
            type Secret = Annotated[
                SecretStr,
                Field(
                    min_length=c.Auth.CREDENTIAL_MIN_LENGTH,
                    max_length=c.Auth.CREDENTIAL_MAX_LENGTH,
                    description="Protected credential value",
                ),
            ]

        class Tokens:
            """Token-related type definitions."""

            type TokenType = c.Auth.TokenTypes
            type ClaimMap = FlextApiTypes.JsonDict

        class Sessions:
            """Session-related type definitions."""

        class Responses:
            """Response payload abstractions."""

        class Managers:
            """Manager-specific supporting types."""

        class Domain:
            """Domain-level literals and shortcuts."""

            type ProviderType = c.Auth.ProviderTypes
            type Role = c.Auth.RoleTypes
            type Permission = c.Auth.PermissionTypes
            type AccessTokens = Literal[
                c.Auth.TokenTypes.ACCESS, c.Auth.TokenTypes.BEARER
            ]
            "Access token types for operations."
            type RefreshTokens = Literal[c.Auth.TokenTypes.REFRESH]
            "Refresh token types."
            type BearerTokens = Literal[
                c.Auth.TokenTypes.BEARER, c.Auth.TokenTypes.ACCESS
            ]
            "Bearer token types."
            type AdminRoles = Literal[c.Auth.RoleTypes.ADMIN]
            "Admin role types."
            type UserRoles = Literal[
                c.Auth.RoleTypes.USER,
                c.Auth.RoleTypes.MODERATOR,
                c.Auth.RoleTypes.GUEST,
            ]
            "User role types."
            type WritePermissions = Literal[
                c.Auth.PermissionTypes.WRITE, c.Auth.PermissionTypes.DELETE
            ]
            "Write permission types."
            type AdminPermissions = Literal[c.Auth.PermissionTypes.ADMIN]
            "Admin permission types."
            type TokenTypeLiteral = Literal[
                c.Auth.TokenTypes.ACCESS,
                c.Auth.TokenTypes.REFRESH,
                c.Auth.TokenTypes.API,
                c.Auth.TokenTypes.BEARER,
            ]
            "Token type literal - references TokenTypes StrEnum members."
            type ProviderTypeLiteral = Literal[
                c.Auth.ProviderTypes.BASIC,
                c.Auth.ProviderTypes.JWT,
                c.Auth.ProviderTypes.OAUTH2,
                c.Auth.ProviderTypes.SAML,
                c.Auth.ProviderTypes.LDAP,
                c.Auth.ProviderTypes.CERTIFICATE,
                c.Auth.ProviderTypes.KERBEROS,
                c.Auth.ProviderTypes.APIKEY,
            ]
            "Provider type literal - references ProviderTypes StrEnum members."
            type RoleTypeLiteral = Literal[
                c.Auth.RoleTypes.ADMIN,
                c.Auth.RoleTypes.USER,
                c.Auth.RoleTypes.MODERATOR,
                c.Auth.RoleTypes.GUEST,
            ]
            "Role type literal - matches RoleTypes StrEnum values exactly."
            type PermissionTypeLiteral = Literal[
                c.Auth.PermissionTypes.READ,
                c.Auth.PermissionTypes.WRITE,
                c.Auth.PermissionTypes.DELETE,
                c.Auth.PermissionTypes.ADMIN,
            ]
            "Permission type literal - matches PermissionTypes StrEnum values exactly."
            type AlgorithmLiteral = Literal[
                c.Auth.Algorithms.HS256,
                c.Auth.Algorithms.RS256,
                c.Auth.Algorithms.ES256,
            ]
            "Algorithm literal - matches Algorithms StrEnum values exactly."

        class Unit:
            """Unit type for operations that return nothing but may fail."""

            class UnitType:
                """Singleton unit type for void operations."""

                __slots__ = ()

                @override
                def __repr__(self) -> str:
                    """Return string representation of Unit type."""
                    return "Unit"

            UNIT = UnitType()

    UserManagement = Auth.UserManagement
    SessionManagement = Auth.SessionManagement
    TokenManagement = Auth.TokenManagement
    Authorization = Auth.Authorization
    Security = Auth.Security

    class Project(FlextApiTypes.Project):
        """Auth project namespace extending API project namespace."""

        type ProjectType = Literal["flext-auth", "flext-core", "flext-api"]

    OAuth2TokenResponse = Auth.OAuth2TokenResponse
    KerberosTicketData = Auth.KerberosTicketData
    HttpResponseData = Auth.HttpResponseData
    Providers = Auth.Providers
    Credentials = Auth.Credentials
    Tokens = Auth.Tokens
    Sessions = Auth.Sessions
    Responses = Auth.Responses
    Managers = Auth.Managers
    Domain = Auth.Domain


t = FlextAuthTypes
__all__ = ["FlextAuthTypes", "t"]

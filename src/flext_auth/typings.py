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

from flext_auth.constants import c
from flext_auth.models import FlextAuthModels as m


class FlextAuthTypes(FlextApiTypes):
    """Authentication-specific type definitions extending t with composition."""

    ProviderConfig = m.Auth.ProviderConfig

    class Auth:
        """Authentication-related type definitions."""

        type AuthMethod = c.AuthMethod
        type AuthStatus = c.AuthStatus
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

            type UserStatus = c.UserStatus
            type UserAction = c.UserAction

        class SessionManagement:
            """Session management type definitions."""

            type SessionStatus = c.SessionStatus
            type SessionAction = c.SessionAction

        class TokenManagement:
            """Token management type definitions."""

            type TokenType = c.TokenType
            type TokenStatus = c.TokenStatus

        class Authorization:
            """Authorization type definitions."""

            type Permission = c.Permission
            type Role = c.Role

        class Security:
            """Security-related type definitions."""

            type SecurityEvent = c.SecurityEvent
            type ThreatLevel = c.ThreatLevel

        class Project:
            """Project type namespace."""

            type ProjectType = c.ProjectType
            AuthProjectConfig = m.Auth.ProviderConfig

        class Providers:
            """Provider-oriented type definitions."""

            # Model reference from m.Auth.Providers
            Metadata = m.Auth.Providers.Metadata
            Registration = m.Auth.ProviderConfig

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

            Basic = m.Auth.Credential
            MultiFactor = m.Auth.CredentialValidation

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
            type ClaimMap = FlextApiTypes.Api.JsonObject
            Claims = FlextApiTypes.Api.JsonObject
            Introspection = FlextApiTypes.Api.JsonObject

        class Sessions:
            """Session-related type definitions."""

            Activity = FlextApiTypes.Api.JsonObject

        class Responses:
            """Response payload abstractions."""

            Authentication = m.Auth.AuthResponse
            AuthenticationPayload = FlextApiTypes.Api.JsonObject

        class Managers:
            """Manager-specific supporting types."""

            UserData = FlextApiTypes.Api.JsonObject
            SessionData = FlextApiTypes.Api.JsonObject
            LogEntry = FlextApiTypes.Api.JsonObject
            AuditEntry = FlextApiTypes.Api.JsonObject
            AttemptData = FlextApiTypes.Api.JsonObject
            AttemptWindow = m.Auth.ValidationResult

        class Domain:
            """Domain-level literals and shortcuts."""

            type ProviderType = c.Auth.ProviderTypes
            type Role = c.Auth.RoleTypes
            type Permission = c.Auth.PermissionTypes
            type AccessTokens = c.AccessTokens
            "Access token types for operations."
            type RefreshTokens = Literal["refresh"]
            "Refresh token types."
            type BearerTokens = c.BearerTokens
            "Bearer token types."
            type AdminRoles = Literal["REDACTED_LDAP_BIND_PASSWORD"]
            "Admin role types."
            type UserRoles = c.UserRoles
            "User role types."
            type WritePermissions = c.WritePermissions
            "Write permission types."
            type AdminPermissions = Literal["REDACTED_LDAP_BIND_PASSWORD"]
            "Admin permission types."
            type TokenTypeLiteral = c.TokenTypeLiteral
            "Token type literal - references TokenTypes StrEnum members."
            type ProviderTypeLiteral = c.ProviderTypeLiteral
            "Provider type literal - references ProviderTypes StrEnum members."
            type RoleTypeLiteral = c.RoleTypeLiteral
            "Role type literal - matches RoleTypes StrEnum values exactly."
            type PermissionTypeLiteral = c.PermissionTypeLiteral
            "Permission type literal - matches PermissionTypes StrEnum values exactly."
            type AlgorithmLiteral = c.AlgorithmLiteral
            "Algorithm literal - matches Algorithms StrEnum values exactly."

        class Unit:
            """Unit type for operations that return nothing but may fail."""

            class UnitType:
                """Singleton unit type for void operations."""

                __slots__: tuple[()] = ()

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

        type ProjectType = c.ProjectType
        AuthProjectConfig = m.Auth.ProviderConfig

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

"""FLEXT Auth Types - Type definitions and aliases.

Uses Pydantic models from flext_auth for consolidated type definitions.
Maintains backward compatibility where possible while enforcing new patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableMapping
from typing import Annotated, Literal, override

from flext_cli import m, t, u
from pydantic import SecretStr

from flext_auth import c


class FlextAuthTypes(t):
    """Authentication-specific type definitions extending t with composition."""

    CONFIGURATION_MAPPING_ADAPTER: m.TypeAdapter[t.ConfigurationMapping] = (
        m.TypeAdapter(t.ConfigurationMapping)
    )
    STR_SEQUENCE_ADAPTER: m.TypeAdapter[t.StrSequence] = m.TypeAdapter(t.StrSequence)
    CONTAINER_VALUE_MAPPING_ADAPTER: m.TypeAdapter[t.ContainerValueMapping] = (
        m.TypeAdapter(t.ContainerValueMapping)
    )

    class Auth:
        """Authentication-related type definitions."""

        type AuthMethod = c.Auth.AuthMethod
        type AuthStatus = c.Auth.AuthStatus
        type CoercedTokenTypes = Annotated[
            c.Auth.TokenTypes,
            m.BeforeValidator(lambda x: x),
        ]
        type CoercedProviderTypes = Annotated[
            c.Auth.ProviderTypes,
            m.BeforeValidator(lambda x: x),
        ]
        type CoercedRoleTypes = Annotated[
            c.Auth.RoleTypes,
            m.BeforeValidator(lambda x: x),
        ]

        class UserManagement:
            """User management type definitions."""

            type UserStatus = c.Auth.UserStatus
            type UserAction = c.Auth.UserAction

        class SessionManagement:
            """Session management type definitions."""

            type SessionStatus = c.Auth.SessionStatus
            type SessionAction = c.Auth.SessionAction

        class TokenManagement:
            """Token management type definitions."""

            type TokenType = c.Auth.AuthTokenType
            type TokenStatus = c.Auth.TokenStatus

        class Authorization:
            """Authorization type definitions."""

            type Permission = c.Auth.Permission
            type Role = c.Auth.Role

        class Security:
            """Security-related type definitions."""

            type SecurityEvent = c.Auth.SecurityEvent
            type ThreatLevel = c.Auth.ThreatLevel

        class Providers:
            """Provider-oriented type definitions."""

            type Key = Annotated[
                str,
                u.Field(
                    min_length=1,
                    max_length=c.Auth.Validation.SHORT_NAME_MAX,
                    pattern="^[a-z0-9](?:[a-z0-9\\-_.]{0,62}[a-z0-9])?$",
                    description="Provider registry key",
                ),
            ]
            type Capability = Annotated[
                str,
                u.Field(
                    min_length=1,
                    max_length=c.Auth.Validation.SHORT_NAME_MAX,
                    pattern="^[a-z][a-z0-9_:-]*$",
                    description="Provider capability identifier",
                ),
            ]
            type CapabilitySet = Annotated[
                frozenset[Capability],
                u.Field(min_length=1, description="Declared capabilities"),
            ]

        class Credentials:
            """Credential payload type definitions."""

            type Username = Annotated[
                str,
                u.Field(
                    min_length=1,
                    max_length=c.Auth.Validation.LONG_NAME_MAX,
                    description="Identity username",
                ),
            ]
            type Password = Annotated[
                str,
                u.Field(
                    min_length=c.Auth.CREDENTIAL_MIN_LENGTH,
                    max_length=c.Auth.CREDENTIAL_MAX_LENGTH,
                    description="Raw credential string",
                ),
            ]
            type Secret = Annotated[
                SecretStr,
                u.Field(
                    min_length=c.Auth.CREDENTIAL_MIN_LENGTH,
                    max_length=c.Auth.CREDENTIAL_MAX_LENGTH,
                    description="Protected credential value",
                ),
            ]

        type TokenRequestType = Literal["access", "refresh", "id", "bearer"]
        "Allowed token types for token generation requests."

        class Tokens:
            """Token-related type definitions."""

            type TokenType = c.Auth.TokenTypes
            type ClaimMap = MutableMapping[str, t.ContainerValue]
            type Claims = MutableMapping[str, t.ContainerValue]
            type Introspection = MutableMapping[str, t.ContainerValue]

        class Sessions:
            """Session-related type definitions."""

            type Activity = MutableMapping[str, t.ContainerValue]

        class Responses:
            """Response payload abstractions."""

            type AuthenticationPayload = MutableMapping[
                str,
                t.ContainerValue,
            ]

        class Managers:
            """Manager-specific supporting types."""

            type UserData = MutableMapping[str, t.ContainerValue]
            type SessionData = MutableMapping[str, t.ContainerValue]
            type LogEntry = MutableMapping[str, t.ContainerValue]
            type AuditEntry = MutableMapping[str, t.ContainerValue]
            type AttemptData = MutableMapping[str, t.ContainerValue]
            type AttemptWindow = tuple[int, int]

        class Domain:
            """Domain-level literals and shortcuts."""

            type ProviderType = c.Auth.ProviderTypes
            type Role = c.Auth.RoleTypes
            type Permission = c.Auth.PermissionTypes
            type AccessTokens = c.Auth.AccessTokens
            "Access token types for operations."
            type RefreshTokens = Literal["refresh"]
            "Refresh token types."
            type BearerTokens = c.Auth.BearerTokens
            "Bearer token types."
            type AdminRoles = Literal["REDACTED_LDAP_BIND_PASSWORD"]
            "Admin role types."
            type UserRoles = c.Auth.UserRoles
            "User role types."
            type WritePermissions = c.Auth.WritePermissions
            "Write permission types."
            type AdminPermissions = Literal["REDACTED_LDAP_BIND_PASSWORD"]
            "Admin permission types."
            type TokenTypeLiteral = c.Auth.TokenTypeLiteral
            "Token type literal - references TokenTypes StrEnum members."
            type ProviderTypeLiteral = c.Auth.ProviderTypeLiteral
            "Provider type literal - references ProviderTypes StrEnum members."
            type RoleTypeLiteral = c.Auth.RoleTypeLiteral
            "Role type literal - matches RoleTypes StrEnum values exactly."
            type PermissionTypeLiteral = c.Auth.PermissionTypeLiteral
            "Permission type literal - matches PermissionTypes StrEnum values exactly."
            type AlgorithmLiteral = c.Auth.AlgorithmLiteral
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

        class Project:
            """Auth project namespace."""

            type ProjectType = c.Auth.ProjectType


t = FlextAuthTypes
__all__: list[str] = ["FlextAuthTypes", "t"]

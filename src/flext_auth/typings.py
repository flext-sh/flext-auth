"""FLEXT Auth Types - Type definitions and aliases.

Uses Pydantic models from flext_auth for consolidated type definitions.
Maintains backward compatibility where possible while enforcing new patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Annotated, Literal, override

from flext_api import FlextApiTypes
from pydantic import BaseModel, BeforeValidator, ConfigDict, Field, SecretStr

from flext_auth import c, m


class FlextAuthTypes(FlextApiTypes):
    """Authentication-specific type definitions extending t with composition."""

    # =========================================================================
    # CORE AUTH TYPES - Mapped to Pydantic Models
    # =========================================================================

    # Core configs mapped to Pydantic models
    ProviderConfig = m.Auth.ProviderConfig

    # =========================================================================
    # AUTHENTICATION DOMAIN TYPE CLASSES
    # =========================================================================

    class Auth:
        """Authentication-related type definitions."""

        type AuthMethod = Literal["basic", "jwt", "oauth2", "apikey"]
        type AuthStatus = Literal[
            "authenticated",
            "unauthenticated",
            "expired",
            "invalid",
        ]

        # Coerced enum types for Pydantic Field (Annotated[Enum, BeforeValidator])
        type CoercedTokenTypes = Annotated[
            c.Auth.TokenTypes,
            BeforeValidator(lambda x: x),
        ]
        type CoercedProviderTypes = Annotated[
            c.Auth.ProviderTypes,
            BeforeValidator(lambda x: x),
        ]
        type CoercedRoleTypes = Annotated[
            c.Auth.RoleTypes,
            BeforeValidator(lambda x: x),
        ]

        class UserManagement:
            """User management type definitions."""

            type UserStatus = Literal["active", "inactive", "locked", "pending"]
            type UserAction = Literal[
                "create",
                "update",
                "delete",
                "activate",
                "deactivate",
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
                "read",
                "write",
                "delete",
                "REDACTED_LDAP_BIND_PASSWORD",
            ]
            type Role = Literal[
                "user", "moderator", "REDACTED_LDAP_BIND_PASSWORD", "guest"
            ]

        class Security:
            """Security-related type definitions."""

            type SecurityEvent = Literal[
                "login_success",
                "login_failure",
                "token_created",
                "token_revoked",
            ]
            type ThreatLevel = Literal["low", "medium", "high", "critical"]

        # =========================================================================
        # =========================================================================

        class Project:
            """Project type namespace."""

            type ProjectType = Literal["flext-auth", "flext-core", "flext-api"]

            class AuthProjectConfig(BaseModel):
                """Project configuration structure."""

                model_config = ConfigDict(frozen=False, extra="forbid")

        # Note: ProviderConfig is now aliased to m.ProviderConfig above

        class OAuth2TokenResponse(BaseModel):
            """OAuth2 token response structure."""

            model_config = ConfigDict(frozen=False, extra="forbid")

            access_token: str = Field(default="")
            token_type: str = Field(default="")
            expires_in: int = Field(default=0)
            refresh_token: str = Field(default="")
            scope: str = Field(default="")
            id_token: str = Field(default="")

        class KerberosTicketData(BaseModel):
            """Kerberos ticket data structure."""

            model_config = ConfigDict(frozen=False, extra="forbid")

            ticket: str = Field(default="")
            session_key: str = Field(default="")
            principal: str = Field(default="")
            realm: str = Field(default="")
            start_time: str = Field(default="")
            end_time: str = Field(default="")
            renew_till: str = Field(default="")
            flags: list[str] = Field(default_factory=list)

        class HttpResponseData(BaseModel):
            """HTTP response data structure."""

            model_config = ConfigDict(frozen=False, extra="forbid")

            status_code: int = Field(default=0)
            headers: dict[str, str] = Field(default_factory=dict)
            body: str = Field(default="")
            json_data: FlextApiTypes.JsonDict = Field(default_factory=dict)
            error: str = Field(default="")
            success: bool = Field(default=False)

        class Providers:
            """Provider-oriented type definitions."""

            type Key = Annotated[
                str,
                Field(
                    min_length=1,
                    max_length=c.Auth.Validation.SHORT_NAME_MAX,
                    pattern=r"^[a-z0-9](?:[a-z0-9\-_.]{0,62}[a-z0-9])?$",
                    description="Provider registry key",
                ),
            ]
            type Capability = Annotated[
                str,
                Field(
                    min_length=1,
                    max_length=c.Auth.Validation.SHORT_NAME_MAX,
                    pattern=r"^[a-z][a-z0-9_:-]*$",
                    description="Provider capability identifier",
                ),
            ]
            type CapabilitySet = Annotated[
                frozenset[Capability],
                Field(min_length=1, description="Declared capabilities"),
            ]

            class Metadata(BaseModel):
                """Provider metadata contract returned by providers."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                name: str = Field(default="")
                version: str = Field(default="")
                capabilities: tuple[str, ...] = Field(default_factory=tuple)
                description: str = Field(default="")
                documentation_url: str = Field(default="")
                maintainers: tuple[str, ...] = Field(default_factory=tuple)
                extras: FlextApiTypes.JsonDict = Field(default_factory=dict)

            class Registration(BaseModel):
                """Payload used when registering providers in registries."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                key: str = Field(default="")
                provider: FlextAuthTypes.ContainerValue = Field(
                    default=None,
                )  # Provider instance - typed as FlextAuthTypes.ContainerValue to avoid circular import
                metadata: dict[str, FlextAuthTypes.ContainerValue] = Field(
                    default_factory=dict
                )
                configuration: FlextApiTypes.JsonDict = Field(default_factory=dict)

        class Credentials:
            """Credential payload type definitions."""

            type Username = Annotated[
                str,
                Field(
                    min_length=1,  # Use literal value instead of constant access
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

            class Basic(BaseModel):
                """Standard username/password credentials payload."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                username: str = Field(default="")
                password: str = Field(default="")
                remember_me: bool = Field(default=False)
                metadata: FlextApiTypes.JsonDict = Field(default_factory=dict)

            class MultiFactor(BaseModel):
                """Extended credential payload supporting MFA."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                username: str = Field(default="")
                password: str = Field(default="")
                factors: tuple[str, ...] = Field(default_factory=tuple)
                otp: str = Field(default="")
                metadata: FlextApiTypes.JsonDict = Field(default_factory=dict)

        class Tokens:
            """Token-related type definitions."""

            # AuthToken type defined in models.py
            type TokenType = c.Auth.TokenTypes
            type ClaimMap = FlextApiTypes.JsonDict

            class Claims(BaseModel):
                """Normalized token claims representation."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                subject: str = Field(default="")
                issuer: str = Field(default="")
                audience: tuple[str, ...] = Field(default_factory=tuple)
                scopes: tuple[str, ...] = Field(default_factory=tuple)
                session_id: str = Field(default="")
                issued_at: str = Field(default="")
                expires_at: str = Field(default="")
                metadata: FlextApiTypes.JsonDict = Field(default_factory=dict)

            class Introspection(BaseModel):
                """Token introspection response payload."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                active: bool = Field(default=False)
                token_type: str = Field(default="")
                subject: str = Field(default="")
                client_id: str = Field(default="")
                expires_at: str = Field(default="")
                issued_at: str = Field(default="")
                scope: tuple[str, ...] = Field(default_factory=tuple)
                metadata: FlextApiTypes.JsonDict = Field(default_factory=dict)

        class Sessions:
            """Session-related type definitions."""

            # Session type defined in models.py

            # Snapshot definitions removed to avoid circular imports

            class Activity(BaseModel):
                """Session activity entry."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                session_id: str = Field(default="")
                occurred_at: str = Field(default="")
                event: str = Field(default="")
                context: FlextApiTypes.JsonDict = Field(default_factory=dict)

        class Responses:
            """Response payload abstractions."""

            # Authentication response type - defined locally to avoid circular imports
            class Authentication(BaseModel):
                """Authentication response structure."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                success: bool = Field(default=False)
                identity: FlextApiTypes.JsonDict = Field(
                    default_factory=dict,
                )  # Will be Identity from models
                token: FlextApiTypes.JsonDict = Field(
                    default_factory=dict,
                )  # Will be AuthToken from models
                session: FlextApiTypes.JsonDict = Field(
                    default_factory=dict,
                )  # Will be Session from models
                message: str = Field(default="")
                metadata: FlextApiTypes.JsonDict = Field(default_factory=dict)

            class AuthenticationPayload(BaseModel):
                """Structured authentication response for transports."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                success: bool = Field(default=False)
                # identity, session, token types defined in models.py
                issued_at: str = Field(default="")
                expires_at: str = Field(default="")
                metadata: FlextApiTypes.JsonDict = Field(default_factory=dict)

        class Managers:
            """Manager-specific supporting types."""

            class UserData(BaseModel):
                """User data structure for storage."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                unique_id: str = Field(default="")
                id: str = Field(default="")
                identity_id: str = Field(default="")
                name: str = Field(default="")
                contact: str = Field(default="")
                credential_hash: str = Field(default="")
                full_name: str | None = Field(default=None)
                is_active: bool = Field(default=True)
                roles: list[str] = Field(default_factory=list)
                permissions: list[str] = Field(default_factory=list)
                failed_attempts: int = Field(default=0)
                locked_until: str | None = Field(default=None)
                last_access: str | None = Field(default=None)

            class SessionData(BaseModel):
                """Session data structure for storage."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                id: str = Field(default="")
                unique_id: str = Field(default="")
                identity_id: str = Field(default="")
                session_token: str = Field(default="")
                expires_at: str = Field(default="")
                is_active: bool = Field(default=True)
                ip_address: str | None = Field(default=None)
                user_agent: str | None = Field(default=None)
                last_accessed: str = Field(default="")

            class LogEntry(BaseModel):
                """Structured log entry for audit logging."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                event: str = Field(default="")
                occurred_at: str = Field(default="")
                # actor type defined in models.py
                context: FlextApiTypes.JsonDict = Field(default_factory=dict)
                event_type: str = Field(default="")
                timestamp: str = Field(default="")
                metadata: FlextApiTypes.JsonDict = Field(default_factory=dict)

            class AuditEntry(BaseModel):
                """Structured audit log entry."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                event: str = Field(default="")
                occurred_at: str = Field(default="")
                # actor type defined in models.py
                context: FlextApiTypes.JsonDict = Field(default_factory=dict)

            class AttemptData(BaseModel):
                """Failed attempt data structure."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                identity_id: str = Field(default="")
                attempts: list[str] = Field(default_factory=list)
                locked_until: str | None = Field(default=None)
                last_attempt: str | None = Field(default=None)

            class AttemptWindow(BaseModel):
                """Failed attempt tracking window."""

                model_config = ConfigDict(frozen=False, extra="forbid")

                identity_id: str = Field(default="")
                attempts: tuple[str, ...] = Field(default_factory=tuple)
                locked_until: str | None = Field(default=None)

        class Domain:
            """Domain-level literals and shortcuts."""

            type ProviderType = c.Auth.ProviderTypes
            type Role = c.Auth.RoleTypes
            type Permission = c.Auth.PermissionTypes

            # Literal types moved from constants.py per architecture rules
            type AccessTokens = Literal[
                c.Auth.TokenTypes.ACCESS, c.Auth.TokenTypes.BEARER
            ]
            """Access token types for operations."""
            type RefreshTokens = Literal[c.Auth.TokenTypes.REFRESH]
            """Refresh token types."""
            type BearerTokens = Literal[
                c.Auth.TokenTypes.BEARER, c.Auth.TokenTypes.ACCESS
            ]
            """Bearer token types."""
            type AdminRoles = Literal[c.Auth.RoleTypes.ADMIN]
            """Admin role types."""
            type UserRoles = Literal[
                c.Auth.RoleTypes.USER,
                c.Auth.RoleTypes.MODERATOR,
                c.Auth.RoleTypes.GUEST,
            ]
            """User role types."""
            type WritePermissions = Literal[
                c.Auth.PermissionTypes.WRITE,
                c.Auth.PermissionTypes.DELETE,
            ]
            """Write permission types."""
            type AdminPermissions = Literal[c.Auth.PermissionTypes.ADMIN]
            """Admin permission types."""

            type TokenTypeLiteral = Literal[
                c.Auth.TokenTypes.ACCESS,
                c.Auth.TokenTypes.REFRESH,
                c.Auth.TokenTypes.API,
                c.Auth.TokenTypes.BEARER,
            ]
            """Token type literal - references TokenTypes StrEnum members."""

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
            """Provider type literal - references ProviderTypes StrEnum members."""

            type RoleTypeLiteral = Literal[
                c.Auth.RoleTypes.ADMIN,
                c.Auth.RoleTypes.USER,
                c.Auth.RoleTypes.MODERATOR,
                c.Auth.RoleTypes.GUEST,
            ]
            """Role type literal - matches RoleTypes StrEnum values exactly."""

            type PermissionTypeLiteral = Literal[
                c.Auth.PermissionTypes.READ,
                c.Auth.PermissionTypes.WRITE,
                c.Auth.PermissionTypes.DELETE,
                c.Auth.PermissionTypes.ADMIN,
            ]
            """Permission type literal - matches PermissionTypes StrEnum values exactly."""

            type AlgorithmLiteral = Literal[
                c.Auth.Algorithms.HS256,
                c.Auth.Algorithms.RS256,
                c.Auth.Algorithms.ES256,
            ]
            """Algorithm literal - matches Algorithms StrEnum values exactly."""

        class Unit:
            """Unit type for operations that return nothing but may fail."""

            class UnitType:
                """Singleton unit type for void operations."""

                __slots__ = ()

                @override
                def __repr__(self) -> str:
                    """Return string representation of Unit type."""
                    return "Unit"

            # Singleton instance
            UNIT = UnitType()


t = FlextAuthTypes
__all__ = ["FlextAuthTypes", "t"]

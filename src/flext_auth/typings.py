"""Domain-specific authentication type definitions aligned with flext-core guidance."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, Literal, TypedDict

from flext_core import FlextTypes
from pydantic import Field, SecretStr

from flext_auth.constants import FlextAuthConstants as c


class FlextAuthTypes(FlextTypes):
    """Authentication-specific type definitions extending t with composition."""

    # =========================================================================
    # CORE AUTH TYPES - Using dict for pydantic compatibility
    # =========================================================================

    class UserDict(TypedDict, total=False):
        """User dictionary structure."""

        id: str
        username: str
        email: str
        full_name: str
        is_active: bool
        roles: list[str]
        permissions: list[str]
        created_at: datetime
        updated_at: datetime
        last_login: datetime

    class SessionDict(TypedDict, total=False):
        """Session dictionary structure for backward compatibility."""

        id: str
        user_id: str
        session_token: str
        expires_at: datetime
        created_at: datetime
        last_accessed_at: datetime
        is_active: bool

    class AuthenticationResponseDict(TypedDict, total=False):
        """Authentication response dictionary structure for backward compatibility."""

        user: FlextAuthTypes.Managers.UserData
        session: FlextAuthTypes.Managers.SessionData
        jwt_token: str
        authenticated: bool
        success: bool
        tokens: FlextAuthTypes.Tokens.ClaimMap

    # =========================================================================
    # AUTHENTICATION DOMAIN TYPE CLASSES
    # =========================================================================

    class Authentication:
        """Authentication-related type definitions."""

        type AuthMethod = Literal["basic", "jwt", "oauth2", "apikey"]
        type AuthStatus = Literal[
            "authenticated",
            "unauthenticated",
            "expired",
            "invalid",
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

        type Permission = Literal["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]
        type Role = Literal["user", "moderator", "REDACTED_LDAP_BIND_PASSWORD", "guest"]

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
    # PROJECT TYPE CLASSES (for test compatibility)
    # =========================================================================

    class Project:
        """Project type namespace."""

        type ProjectType = Literal["flext-auth", "flext-core", "flext-api"]

        class AuthProjectConfig(TypedDict, total=False):
            """Project configuration structure."""

    class ProviderConfig(TypedDict, total=False):
        """Provider configuration dictionary structure."""

        provider_type: str
        secret_key: str
        algorithm: str
        token_expiry_minutes: int
        refresh_expiry_days: int
        client_id: str
        client_secret: str
        authorization_url: str
        token_url: str
        redirect_uri: str
        scope: str
        audience: str
        issuer: str
        realm: str
        kdc_host: str
        kdc_port: int
        service_principal: str
        keytab_path: str
        entity_id: str
        sso_url: str
        slo_url: str
        x509_cert: str
        ldap_url: str
        bind_dn: str
        base_dn: str
        search_filter: str

    class OAuth2TokenResponse(TypedDict, total=False):
        """OAuth2 token response structure."""

        access_token: str
        token_type: str
        expires_in: int
        refresh_token: str
        scope: str
        id_token: str

    class KerberosTicketData(TypedDict, total=False):
        """Kerberos ticket data structure."""

        ticket: str
        session_key: str
        principal: str
        realm: str
        start_time: datetime
        end_time: datetime
        renew_till: datetime
        flags: list[str]

    class HttpResponseData(TypedDict, total=False):
        """HTTP response data structure."""

        status_code: int
        headers: dict[str, str]
        body: str
        json: t.JsonDict
        error: str
        success: bool

    class Providers:
        """Provider-oriented type definitions."""

        type Key = Annotated[
            str,
            Field(
                min_length=1,
                max_length=64,
                pattern=r"^[a-z0-9](?:[a-z0-9\-_.]{0,62}[a-z0-9])?$",
                description="Provider registry key",
            ),
        ]
        type Capability = Annotated[
            str,
            Field(
                min_length=1,
                max_length=64,
                pattern=r"^[a-z][a-z0-9_:-]*$",
                description="Provider capability identifier",
            ),
        ]
        type CapabilitySet = Annotated[
            frozenset[FlextAuthTypes.Providers.Capability],
            Field(min_length=1, description="Declared capabilities"),
        ]

        class Metadata(TypedDict, total=False):
            """Provider metadata contract returned by providers."""

            name: FlextAuthTypes.Providers.Key
            version: str
            capabilities: tuple[FlextAuthTypes.Providers.Capability, ...]
            description: str
            documentation_url: str
            maintainers: tuple[str, ...]
            extras: t.JsonDict

        class Registration(TypedDict, total=False):
            """Payload used when registering providers in registries."""

            key: FlextAuthTypes.Providers.Key
            provider: (
                object  # Provider instance - typed as object to avoid circular import
            )
            metadata: FlextAuthTypes.Providers.Metadata
            configuration: t.JsonDict

    class Credentials:
        """Credential payload type definitions."""

        type Username = Annotated[
            str,
            Field(
                min_length=1,  # Use literal value instead of constant access
                max_length=255,  # Use literal value instead of constant access
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

        class Basic(TypedDict, total=False):
            """Standard username/password credentials payload."""

            username: FlextAuthTypes.Credentials.Username
            password: FlextAuthTypes.Credentials.Secret
            remember_me: bool
            metadata: t.JsonDict

        class MultiFactor(TypedDict, total=False):
            """Extended credential payload supporting MFA."""

            username: FlextAuthTypes.Credentials.Username
            password: FlextAuthTypes.Credentials.Secret
            factors: tuple[str, ...]
            otp: str
            metadata: t.JsonDict

    class Tokens:
        """Token-related type definitions."""

        # AuthToken type defined in models.py
        type TokenType = c.Auth.TokenTypes
        type ClaimMap = t.JsonDict

        class Claims(TypedDict, total=False):
            """Normalized token claims representation."""

            subject: str
            issuer: str
            audience: tuple[str, ...]
            scopes: tuple[str, ...]
            session_id: str
            issued_at: datetime
            expires_at: datetime
            metadata: t.JsonDict

        class Introspection(TypedDict, total=False):
            """Token introspection response payload."""

            active: bool
            token_type: FlextAuthTypes.Tokens.TokenType
            subject: str
            client_id: str
            expires_at: datetime
            issued_at: datetime
            scope: tuple[str, ...]
            metadata: t.JsonDict

    class Sessions:
        """Session-related type definitions."""

        # Session type defined in models.py

        # Snapshot definitions removed to avoid circular imports

        class Activity(TypedDict, total=False):
            """Session activity entry."""

            session_id: str
            occurred_at: datetime
            event: str
            context: t.JsonDict

    class Responses:
        """Response payload abstractions."""

        # Authentication response type - defined locally to avoid circular imports
        class Authentication(TypedDict, total=False):
            """Authentication response structure."""

            success: bool
            identity: t.JsonDict  # Will be Identity from models
            token: t.JsonDict  # Will be AuthToken from models
            session: t.JsonDict  # Will be Session from models
            message: str
            metadata: t.JsonDict

        class AuthenticationPayload(TypedDict, total=False):
            """Structured authentication response for transports."""

            success: bool
            # identity, session, token types defined in models.py
            issued_at: datetime
            expires_at: datetime
            metadata: t.JsonDict

    class Managers:
        """Manager-specific supporting types."""

        class UserData(TypedDict, total=False):
            """User data structure for storage."""

            unique_id: str
            id: str
            identity_id: str
            name: str
            contact: str
            credential_hash: str
            full_name: str | None
            is_active: bool
            roles: list[str]
            permissions: list[str]
            failed_attempts: int
            locked_until: datetime | None
            last_access: datetime | None

        class SessionData(TypedDict, total=False):
            """Session data structure for storage."""

            id: str
            unique_id: str
            identity_id: str
            session_token: str
            expires_at: datetime
            is_active: bool
            ip_address: str | None
            user_agent: str | None
            last_accessed: datetime

        class LogEntry(TypedDict, total=False):
            """Structured log entry for audit logging."""

            event: str
            occurred_at: datetime
            # actor type defined in models.py
            context: t.JsonDict
            event_type: str
            timestamp: datetime
            metadata: t.JsonDict

        class AuditEntry(TypedDict, total=False):
            """Structured audit log entry."""

            event: str
            occurred_at: datetime
            # actor type defined in models.py
            context: t.JsonDict

        class AttemptData(TypedDict, total=False):
            """Failed attempt data structure."""

            identity_id: str
            attempts: list[datetime]
            locked_until: datetime | None
            last_attempt: datetime | None

        class AttemptWindow(TypedDict, total=False):
            """Failed attempt tracking window."""

            identity_id: str
            attempts: tuple[datetime, ...]
            locked_until: datetime | None

    class Domain:
        """Domain-level literals and shortcuts."""

        type ProviderType = c.Auth.ProviderTypes
        type Role = c.Auth.RoleTypes
        type Permission = c.Auth.PermissionTypes

        # Literal types moved from constants.py per architecture rules
        type AccessTokens = Literal[c.Auth.TokenTypes.ACCESS, c.Auth.TokenTypes.BEARER]
        """Access token types for operations."""
        type RefreshTokens = Literal[c.Auth.TokenTypes.REFRESH]
        """Refresh token types."""
        type BearerTokens = Literal[c.Auth.TokenTypes.BEARER, c.Auth.TokenTypes.ACCESS]
        """Bearer token types."""
        type AdminRoles = Literal[c.Auth.RoleTypes.ADMIN]
        """Admin role types."""
        type UserRoles = Literal[
            c.Auth.RoleTypes.USER, c.Auth.RoleTypes.MODERATOR, c.Auth.RoleTypes.GUEST
        ]
        """User role types."""
        type WritePermissions = Literal[
            c.Auth.PermissionTypes.WRITE, c.Auth.PermissionTypes.DELETE
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

            def __repr__(self) -> str:
                """Return string representation of Unit type."""
                return "Unit"

        # Singleton instance
        UNIT = UnitType()

    class Auth:
        """Auth types namespace for cross-project access.

        Provides organized access to all Auth types for other FLEXT projects.
        Usage: Other projects can reference `t.Auth.Providers.*`, `t.Auth.Credentials.*`, etc.
        This enables consistent namespace patterns for cross-project type access.

        Examples:
            from flext_auth.typings import t
            provider_key: t.Auth.Providers.Key = ...
            credentials: t.Auth.Credentials.Basic = ...

        Note: Namespace composition via inheritance - no aliases needed.
        Access parent namespaces directly through inheritance.

        """


t = FlextAuthTypes  # Runtime alias (not TypeAlias to avoid PYI042)

__all__ = ["FlextAuthTypes", "t"]

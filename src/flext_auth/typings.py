"""Domain-specific authentication type definitions aligned with flext-core guidance."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated, TypedDict

from flext_core import FlextTypes
from pydantic import Field, SecretStr

from flext_auth.constants import FlextAuthConstants, PermissionType, RoleType
from flext_auth.models import FlextAuthModels
from flext_auth.providers.base import FlextAuthBaseProvider


class FlextAuthTypes(FlextTypes):
    """Authentication-specific type definitions extending FlextTypes."""

    # =========================================================================
    # DOMAIN TYPE CLASSES (for test compatibility)
    # =========================================================================

    class Authentication:
        """Authentication domain type namespace."""

    class UserManagement:
        """User management domain type namespace."""

    class SessionManagement:
        """Session management domain type namespace."""

    class TokenManagement:
        """Token management domain type namespace."""

    class Authorization:
        """Authorization domain type namespace."""

    # =========================================================================
    # TYPED DICT DEFINITIONS (for test compatibility)
    # =========================================================================

    class UserDict(TypedDict, total=False):
        """User dictionary structure for backward compatibility."""

        id: str
        username: str
        email: str
        full_name: str
        is_active: bool
        roles: list[str]
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

        user: dict[str, object]
        session: dict[str, object]
        jwt_token: str
        authenticated: bool
        success: bool
        tokens: dict[str, object]

    # =========================================================================
    # PROJECT TYPE CLASSES (for test compatibility)
    # =========================================================================

    class Project:
        """Project type namespace."""

        type ProjectType = FlextAuthConstants.ProjectType

        class AuthProjectConfig(TypedDict, total=False):
            """Project configuration structure."""

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
            extras: FlextTypes.JsonDict

        class Registration(TypedDict, total=False):
            """Payload used when registering providers in registries."""

            key: FlextAuthTypes.Providers.Key
            provider: FlextAuthBaseProvider
            metadata: FlextAuthTypes.Providers.Metadata
            configuration: FlextTypes.JsonDict

    class Credentials:
        """Credential payload type definitions."""

        type Username = Annotated[
            str,
            Field(
                min_length=FlextAuthConstants.IDENTITY_MIN_LENGTH,
                max_length=FlextAuthConstants.IDENTITY_MAX_LENGTH,
                description="Identity username",
            ),
        ]
        type Password = Annotated[
            str,
            Field(
                min_length=FlextAuthConstants.CREDENTIAL_MIN_LENGTH,
                max_length=FlextAuthConstants.CREDENTIAL_MAX_LENGTH,
                description="Raw credential string",
            ),
        ]
        type Secret = Annotated[
            SecretStr,
            Field(
                min_length=FlextAuthConstants.CREDENTIAL_MIN_LENGTH,
                max_length=FlextAuthConstants.CREDENTIAL_MAX_LENGTH,
                description="Protected credential value",
            ),
        ]

        class Basic(TypedDict, total=False):
            """Standard username/password credentials payload."""

            username: FlextAuthTypes.Credentials.Username
            password: FlextAuthTypes.Credentials.Secret
            remember_me: bool
            metadata: FlextTypes.JsonDict

        class MultiFactor(TypedDict, total=False):
            """Extended credential payload supporting MFA."""

            username: FlextAuthTypes.Credentials.Username
            password: FlextAuthTypes.Credentials.Secret
            factors: tuple[str, ...]
            otp: str
            metadata: FlextTypes.JsonDict

    class Tokens:
        """Token-related type definitions."""

        type AuthToken = FlextAuthModels.AuthToken
        type TokenType = FlextAuthConstants.TokenType
        type ClaimMap = FlextTypes.JsonDict

        class Claims(TypedDict, total=False):
            """Normalized token claims representation."""

            subject: str
            issuer: str
            audience: tuple[str, ...]
            scopes: tuple[str, ...]
            session_id: str
            issued_at: datetime
            expires_at: datetime
            metadata: FlextTypes.JsonDict

        class Introspection(TypedDict, total=False):
            """Token introspection response payload."""

            active: bool
            token_type: FlextAuthTypes.Tokens.TokenType
            subject: str
            client_id: str
            expires_at: datetime
            issued_at: datetime
            scope: tuple[str, ...]
            metadata: FlextTypes.JsonDict

    class Sessions:
        """Session-related type definitions."""

        type Session = FlextAuthModels.Session

        class Snapshot(TypedDict, total=False):
            """Session snapshot used for auditing."""

            session: FlextAuthModels.Session
            issued_at: datetime
            last_seen_at: datetime
            metadata: FlextTypes.JsonDict

        class Activity(TypedDict, total=False):
            """Session activity entry."""

            session_id: str
            occurred_at: datetime
            event: str
            context: FlextTypes.JsonDict

    class Security:
        """Security and credential validation types."""

        class CredentialStrength(TypedDict):
            """Credential strength analysis result."""

            is_valid: bool
            length: int
            errors: tuple[str, ...]

    class Responses:
        """Response payload abstractions."""

        type Authentication = FlextAuthModels.AuthResponse

        class AuthenticationPayload(TypedDict, total=False):
            """Structured authentication response for transports."""

            success: bool
            identity: FlextAuthModels.Identity
            session: FlextAuthModels.Session
            token: FlextAuthModels.AuthToken
            issued_at: datetime
            expires_at: datetime
            metadata: FlextTypes.JsonDict

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
            actor: FlextAuthModels.Identity | None
            context: FlextTypes.JsonDict
            event_type: str
            timestamp: datetime
            metadata: FlextTypes.JsonDict

        class AuditEntry(TypedDict, total=False):
            """Structured audit log entry."""

            event: str
            occurred_at: datetime
            actor: FlextAuthModels.Identity | None
            context: FlextTypes.JsonDict

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

        type ProviderType = FlextAuthConstants.ProviderType
        type Role = RoleType
        type Permission = PermissionType

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


__all__ = ["FlextAuthTypes"]

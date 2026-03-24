"""FLEXT Auth Models - Single generic class with consolidated Pydantic models.

Uses Python 3.13+ syntax, generic patterns, and SOLID principles for all
authentication domain models. One FlextAuthModels class with nested models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import UserDict
from collections.abc import Mapping
from datetime import UTC, datetime
from typing import Annotated, ClassVar, Literal, Self

import bcrypt
from flext_api import FlextApiModels
from flext_core import r
from pydantic import ConfigDict, Field

from flext_auth import c, t


class FlextAuthModels(FlextApiModels):
    """Single generic authentication models class with nested Pydantic models.

    All authentication domain models consolidated with validation, composition,
    and SOLID principles. Uses Python 3.13+ syntax and flext-core patterns.
    """

    # =========================================================================
    # AUTH NAMESPACE - Authentication domain models
    # =========================================================================

    class Auth:
        """Auth namespace for cross-project access.

        All authentication domain models consolidated with validation, composition,
        and SOLID principles. Uses Python 3.13+ syntax and flext-core patterns.
        """

        # =========================================================================
        # PASSWORD UTILITIES - Password hashing and verification
        # =========================================================================

        class PasswordUtil:
            """Password utilities for authentication."""

            @staticmethod
            def hash_password(password: str) -> str:
                """Hash a password using bcrypt."""
                salt = bcrypt.gensalt(rounds=c.Auth.ModelValidation.BCRYPT_ROUNDS)
                return bcrypt.hashpw(password.encode(), salt).decode()

            @staticmethod
            def verify_password(password: str, hashed: str) -> bool:
                """Verify a password against its hash."""
                return bcrypt.checkpw(password.encode(), hashed.encode())

        # =========================================================================
        # GENERIC VALIDATION RESULT - Single model for all validations
        # =========================================================================

        class ValidationResult(FlextApiModels.Value):
            """Generic validation result for any operation (immutable value t.NormalizedValue)."""

            is_valid: Annotated[bool, Field(..., description="Validation outcome")]
            data: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Result data",
                ),
            ]
            error: Annotated[str, Field(default="", description="Error message")]
            metadata: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Additional metadata",
                ),
            ]

            @property
            def status(self) -> str:
                """Human-readable validation status."""
                if self.is_valid:
                    return "valid"
                if not self.error:
                    return "invalid"
                return f"invalid: {self.error}"

        # =========================================================================
        # TOKEN MODELS - Generic token handling
        # =========================================================================

        class TokenPayload(FlextApiModels.Value):
            """Generic JWT token payload (immutable value t.NormalizedValue)."""

            sub: Annotated[str, Field(..., description="Subject (identity ID)")]
            exp: Annotated[int, Field(..., description="Expiration timestamp (UNIX)")]
            iat: Annotated[int, Field(..., description="Issued at timestamp (UNIX)")]
            jti: Annotated[str, Field(default="", description="Token ID")]
            iss: Annotated[
                str,
                Field(
                    default="flext-auth",
                    description="Issuer",
                ),
            ]
            aud: Annotated[
                str,
                Field(
                    default="flext-api",
                    description="Audience",
                ),
            ]
            session_id: Annotated[str, Field(default="", description="Session ID")]

        class TokenRequest(FlextApiModels.Value):
            """Generic token generation request (immutable value t.NormalizedValue)."""

            identity_id: Annotated[str, Field(..., description="Identity ID")]
            token_type: Annotated[
                Literal["access", "refresh", "id", "bearer"],
                Field(
                    default="access",
                    description="Token type",
                ),
            ]
            expiry_minutes: Annotated[
                t.PositiveInt,
                Field(
                    default=c.Auth.ModelValidation.DEFAULT_TOKEN_EXPIRY_MINUTES,
                    description="Token expiry",
                ),
            ]
            extra_claims: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Additional claims",
                ),
            ]
            session_id: Annotated[str, Field(default="", description="Session ID")]

        class AuthToken(FlextApiModels.Entity):
            """Generic authentication token entity."""

            identity_id: Annotated[str, Field(..., description="Identity ID")]
            token: Annotated[str, Field(..., description="Token value", exclude=True)]
            expires_at: Annotated[datetime, Field(..., description="Expiration time")]
            token_type: Annotated[
                str,
                Field(
                    description="Token type",
                ),
            ] = "bearer"
            session_id: Annotated[str, Field(description="Session ID")] = ""
            is_revoked: Annotated[
                bool,
                Field(description="Revoked status"),
            ] = False
            refresh_token: Annotated[
                str,
                Field(
                    description="Refresh token",
                    exclude=True,
                ),
            ] = ""

            @property
            def user_id(self) -> str:
                """User ID property for protocol compatibility."""
                return self.identity_id

            @property
            def is_expired(self) -> bool:
                """Check if token is expired."""
                return datetime.now(UTC) > self.expires_at

        # =========================================================================
        # IDENTITY MODELS - Generic identity/user entity
        # =========================================================================

        class AuthIdentityRequest(FlextApiModels.Value):
            """Generic identity creation request (immutable value t.NormalizedValue)."""

            name: Annotated[
                str,
                Field(
                    ...,
                    min_length=c.Auth.Credentials.Username.MIN_LENGTH,
                    max_length=c.Auth.Credentials.Username.MAX_LENGTH,
                    description="Unique identity name",
                ),
            ]
            contact: Annotated[
                t.NonEmptyStr,
                Field(
                    ...,
                    pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
                    description="Contact info (email)",
                ),
            ]
            credential: Annotated[
                str,
                Field(
                    ...,
                    min_length=c.Auth.Credentials.Password.MIN_LENGTH,
                    description="Credential (password/key)",
                    exclude=True,
                ),
            ]
            full_name: Annotated[str, Field(description="Full name")] = ""
            roles: Annotated[
                t.StrSequence,
                Field(
                    default_factory=lambda: ["user"],
                    description="Roles",
                ),
            ]

        class AuthIdentity(FlextApiModels.Entity):
            """Generic identity/user entity with minimal fields."""

            # Reference to PasswordUtil for use in methods
            _password_util: type | None = (
                None  # Will be set to Auth.PasswordUtil at class definition time
            )

            name: Annotated[
                str,
                Field(
                    ...,
                    min_length=c.Auth.Credentials.Username.MIN_LENGTH,
                    max_length=c.Auth.Credentials.Username.MAX_LENGTH,
                    description="Unique identity name",
                ),
            ]
            contact: Annotated[str, Field(..., description="Contact info")]
            credential_hash: Annotated[
                str,
                Field(
                    description="Hashed credential",
                    exclude=True,
                ),
            ] = ""
            full_name: Annotated[str, Field(description="Full name")] = ""
            is_active: Annotated[bool, Field(description="Active status")] = True
            roles: Annotated[
                t.StrSequence,
                Field(
                    default_factory=lambda: ["user"],
                    description="Roles",
                ),
            ]
            permissions: Annotated[
                t.StrSequence,
                Field(
                    default_factory=list,
                    description="Permissions",
                ),
            ]
            failed_attempts: Annotated[
                t.NonNegativeInt,
                Field(description="Failed attempts"),
            ] = 0
            locked_until: Annotated[
                datetime,
                Field(
                    default_factory=lambda: datetime.min.replace(tzinfo=UTC),
                    description="Lock time (datetime.min means not locked)",
                ),
            ]
            last_access: Annotated[
                datetime,
                Field(
                    default_factory=lambda: datetime.min.replace(tzinfo=UTC),
                    description="Last access (datetime.min means never accessed)",
                ),
            ]

            # Additional attributes expected by tests
            token: Annotated[
                str,
                Field(description="Associated token", exclude=True),
            ] = ""
            session_id: Annotated[str, Field(description="Session ID")] = ""

            def is_locked(self) -> bool:
                """Check if identity is locked."""
                if self.locked_until == datetime.min.replace(tzinfo=UTC):
                    return False
                return datetime.now(UTC) < self.locked_until

            def set_credential(self, credential: str) -> r[bool]:
                """Set a new credential with bcrypt hashing."""
                try:
                    self.credential_hash = (
                        FlextAuthModels.Auth.PasswordUtil.hash_password(credential)
                    )
                    return r[bool].ok(value=True)
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as e:
                    return r[bool].fail(f"Failed to hash credential: {e}")

            def verify_credential(self, credential: str) -> r[bool]:
                """Verify a credential against stored hash using bcrypt."""
                try:
                    is_valid = FlextAuthModels.Auth.PasswordUtil.verify_password(
                        credential,
                        self.credential_hash,
                    )
                    return r[bool].ok(is_valid)
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as e:
                    return r[bool].fail(f"Credential verification failed: {e}")

            def with_successful_access(self) -> Self:
                """Record successful access (fluent interface)."""
                self.last_access = datetime.now(UTC)
                self.failed_attempts = 0
                self.locked_until = datetime.min.replace(tzinfo=UTC)
                return self

        # =========================================================================
        # SESSION MODELS - Generic session entity
        # =========================================================================

        class Session(FlextApiModels.Entity):
            """Generic session entity."""

            identity_id: Annotated[str, Field(..., description="Identity ID")]
            session_token: Annotated[
                str,
                Field(..., description="Session token", exclude=True),
            ]
            expires_at: Annotated[datetime, Field(..., description="Expiration time")]
            is_active: Annotated[bool, Field(default=True, description="Active status")]
            ip_address: Annotated[str, Field(default="", description="IP address")]
            user_agent: Annotated[str, Field(default="", description="User agent")]
            last_accessed: Annotated[
                datetime,
                Field(
                    default_factory=lambda: datetime.now(UTC),
                    description="Last access",
                ),
            ]

            @property
            def is_expired(self) -> bool:
                """Check if session is expired."""
                return datetime.now(UTC) > self.expires_at

        # =========================================================================
        # ROLE & PERMISSION MODELS - Generic RBAC
        # =========================================================================

        class Role(FlextApiModels.Entity):
            """Generic role entity."""

            name: Annotated[
                t.NonEmptyStr,
                Field(
                    ...,
                    max_length=c.Auth.ModelValidation.MAX_ROLE_NAME_LENGTH,
                    description="Role name",
                ),
            ]
            description: Annotated[
                str,
                Field(
                    default="",
                    max_length=c.Auth.ModelValidation.MAX_ROLE_DESCRIPTION_LENGTH,
                    description="Description",
                ),
            ]
            permissions: Annotated[
                t.StrSequence,
                Field(
                    default_factory=list,
                    description="Permissions",
                ),
            ]

        class Permission(FlextApiModels.Entity):
            """Generic permission entity."""

            name: Annotated[
                t.NonEmptyStr,
                Field(
                    ...,
                    max_length=c.Auth.ModelValidation.MAX_PERMISSION_NAME_LENGTH,
                    description="Permission",
                ),
            ]
            description: Annotated[
                str,
                Field(
                    default="",
                    max_length=c.Auth.ModelValidation.MAX_PERMISSION_DESCRIPTION_LENGTH,
                    description="Description",
                ),
            ]
            resource: Annotated[str, Field(default="", description="Resource path")]
            action: Annotated[str, Field(default="", description="Action type")]

        # =========================================================================
        # PROVIDER MODELS - Generic provider configuration
        # =========================================================================

        class ProviderConfig(FlextApiModels.Value):
            """Generic provider configuration (immutable value t.NormalizedValue)."""

            model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow")

            name: Annotated[str, Field(..., description="Provider name")]
            type: Annotated[str, Field(..., description="Provider type")]
            enabled: Annotated[bool, Field(default=True, description="Enabled status")]

            # Extended configuration fields (migrated from TypedDict)
            # All optional to support various provider types
            provider_type: str | None = None
            secret_key: str | None = None
            algorithm: str | None = None
            token_expiry_minutes: t.PositiveInt | None = None
            refresh_expiry_days: int | None = None
            client_id: str | None = None
            client_secret: str | None = None
            authorization_endpoint: str | None = None
            token_endpoint: str | None = None
            redirect_uri: str | None = None
            scope: str | None = None
            audience: str | None = None
            issuer: str | None = None
            realm: str | None = None
            kdc_host: str | None = None
            kdc_port: t.PortNumber | None = None
            service_principal: str | None = None
            keytab_path: str | None = None
            entity_id: str | None = None
            sso_url: str | None = None
            slo_url: str | None = None
            x509_cert: str | None = None
            ldap_url: str | None = None
            bind_dn: str | None = None
            base_dn: str | None = None
            search_filter: str | None = None
            flow: str | None = None
            use_pkce: bool | None = None
            token_endpoint_auth_method: str | None = None

            def __contains__(self, key: str) -> bool:
                """Dict-like containment check."""
                return key in self.__class__.model_fields

            @property
            def is_configured(self) -> bool:
                """Check if configured."""
                return bool(self.name and self.type)

        class ProviderConfiguration(UserDict[str, t.ContainerValue]):
            """Provider configuration for authentication providers."""

            def __init__(
                self,
                dict_: Mapping[str, t.ContainerValue] | None = None,
                /,
                **kwargs: t.Scalar,
            ) -> None:
                """Initialize provider configuration with defaults."""
                if dict_ is not None:
                    super().__init__(dict_, **kwargs)
                else:
                    super().__init__(**kwargs)
                # Set defaults if not provided
                if "name" not in self:
                    self["name"] = "default"
                if "version" not in self:
                    self["version"] = "1.0.0"
                if "capabilities" not in self:
                    self["capabilities"] = t.StrSequence()

        class ApiKeyValidation(FlextApiModels.Value):
            """API key validation request (immutable value t.NormalizedValue)."""

            api_key: Annotated[str, Field(..., description="API key to validate")]
            metadata: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Additional validation data",
                ),
            ]

        class ApiKeyData(FlextApiModels.Value):
            """API key data structure (immutable value t.NormalizedValue)."""

            key_hash: Annotated[str, Field(..., description="Hashed API key")]
            name: Annotated[str, Field(..., description="Key name")]
            permissions: Annotated[
                t.StrSequence,
                Field(
                    default_factory=list,
                    description="Key permissions",
                ),
            ]
            is_active: Annotated[
                bool,
                Field(default=True, description="Key active status"),
            ]
            expires_at: Annotated[
                datetime,
                Field(
                    default_factory=lambda: datetime.max.replace(tzinfo=UTC),
                    description="Key expiration (datetime.max means never expires)",
                ),
            ]
            created_at: Annotated[
                datetime,
                Field(
                    default_factory=lambda: datetime.now(UTC),
                    description="Creation time",
                ),
            ]

        class CredentialValidation(FlextApiModels.Value):
            """Credential validation request (immutable value t.NormalizedValue)."""

            username: Annotated[str, Field(..., description="Username")]
            password: Annotated[str, Field(..., description="Password", exclude=True)]
            metadata: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Additional validation data",
                ),
            ]

        # =========================================================================
        # CREDENTIAL MODELS - Generic credential handling
        # =========================================================================

        class Credential(FlextApiModels.Value):
            """Generic credential container (immutable value t.NormalizedValue)."""

            credential_type: Annotated[str, Field(..., description="Credential type")]
            value: Annotated[
                str,
                Field(..., description="Credential value", exclude=True),
            ]
            metadata: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Additional data",
                ),
            ]

        # =========================================================================
        # AUTHENTICATION RESPONSE - Generic response
        # =========================================================================

        class AuthResponse(FlextApiModels.Value):
            """Generic authentication response (immutable value t.NormalizedValue)."""

            success: Annotated[bool, Field(..., description="Authentication success")]
            identity: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Identity data",
                ),
            ]
            token: Annotated[str, Field(default="", description="Token", exclude=True)]
            message: Annotated[str, Field(default="", description="Response message")]
            metadata: Annotated[
                t.JsonObject,
                Field(
                    default_factory=dict,
                    description="Additional data",
                ),
            ]

        # =========================================================================
        # OAUTH2 TOKEN RESPONSE - OAuth2 token exchange result
        # =========================================================================

        class OAuth2TokenResponse(FlextApiModels.Value):
            """OAuth2 token response from token endpoint."""

            access_token: Annotated[str, Field(..., description="Access token")]
            token_type: Annotated[
                str,
                Field(description="Token type"),
            ] = "Bearer"
            expires_in: Annotated[
                t.NonNegativeInt,
                Field(description="Expiry seconds"),
            ] = 3600
            scope: Annotated[str, Field(description="Granted scope")] = ""
            refresh_token: Annotated[
                str,
                Field(
                    description="Refresh token",
                    exclude=True,
                ),
            ] = ""

        # =========================================================================
        # KERBEROS TICKET DATA - Kerberos ticket information
        # =========================================================================

        class KerberosTicketData(FlextApiModels.Value):
            """Kerberos ticket information."""

            ticket: Annotated[str, Field(..., description="Kerberos ticket")]
            principal: Annotated[
                str,
                Field(description="Kerberos principal"),
            ] = ""
            realm: Annotated[str, Field(description="Kerberos realm")] = ""

        # =========================================================================
        # HTTP RESPONSE DATA - Generic HTTP response container
        # =========================================================================

        class HttpResponseData(FlextApiModels.Value):
            """Generic HTTP response data."""

            status_code: Annotated[
                t.HttpStatusCode, Field(..., description="HTTP status code")
            ]
            body: Annotated[str, Field(default="", description="Response body")]
            headers: Annotated[
                t.StrMapping,
                Field(
                    default_factory=dict,
                    description="Response headers",
                ),
            ]

        # =========================================================================
        # PROVIDERS NAMESPACE - Provider metadata and related models
        # =========================================================================

        # =========================================================================
        # REGISTRY WRAPPER MODELS - Internal registry wrappers
        # =========================================================================

        class ProviderWrapper(FlextApiModels.Value):
            """Wrapper for auth provider instances."""

            model_config: ClassVar[ConfigDict] = ConfigDict(
                arbitrary_types_allowed=True
            )

            category: Annotated[str, Field(description="Provider category")]
            provider: Annotated[
                t.NormalizedValue, Field(description="Provider instance")
            ]

        class ConfigWrapper(FlextApiModels.Value):
            """Protocol-conformant wrapper for config data."""

            category: Annotated[str, Field(description="Config category")]
            data: Annotated[t.ConfigurationMapping, Field(description="Config data")]

        class MetadataWrapper(FlextApiModels.Value):
            """Protocol-conformant wrapper for metadata."""

            category: Annotated[str, Field(description="Metadata category")]
            data: Annotated[t.NormalizedValue, Field(description="Metadata")]

        class Providers:
            """Provider-related models namespace."""

            class Metadata(FlextApiModels.Value):
                """Provider metadata for registry."""

                name: Annotated[str, Field(..., description="Provider name")]
                version: Annotated[
                    str,
                    Field(description="Provider version"),
                ] = "1.0.0"
                capabilities: Annotated[
                    tuple[str, ...],
                    Field(
                        default_factory=tuple,
                        description="Provider capabilities",
                    ),
                ]
                extras: Annotated[
                    t.JsonObject,
                    Field(
                        default_factory=dict,
                        description="Extra metadata",
                    ),
                ]

            class Registration(FlextApiModels.Value):
                """Provider registration payload (immutable value t.NormalizedValue)."""

                name: Annotated[str, Field(..., description="Provider name")]
                provider_type: Annotated[
                    str,
                    Field(..., description="Provider type"),
                ]


# Short aliases
m = FlextAuthModels

__all__ = ["FlextAuthModels", "m"]

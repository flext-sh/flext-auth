"""FLEXT Auth Models - Single generic class with consolidated Pydantic models.

Uses Python 3.13+ syntax, generic patterns, and SOLID principles for all
authentication domain models. One FlextAuthModels class with nested models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated, ClassVar, Self

import bcrypt
from flext_cli import m

from flext_auth import c, p, r, t, u


class FlextAuthModels(m):
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

        class ValidationResult(m.Value):
            """Generic validation result for any operation (immutable value object)."""

            valid: Annotated[bool, u.Field(..., description="Validation outcome")]
            data: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Result data"
            )
            error: Annotated[str, u.Field(description="Error message")] = ""
            metadata: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Additional metadata"
            )

            @property
            def status(self) -> str:
                """Human-readable validation status."""
                if self.valid:
                    return "valid"
                if not self.error:
                    return "invalid"
                return f"invalid: {self.error}"

        # =========================================================================
        # TOKEN MODELS - Generic token handling
        # =========================================================================

        class TokenPayload(m.Value):
            """Generic JWT token payload (immutable value object)."""

            sub: Annotated[str, u.Field(..., description="Subject (identity ID)")]
            exp: Annotated[int, u.Field(..., description="Expiration timestamp (UNIX)")]
            iat: Annotated[int, u.Field(..., description="Issued at timestamp (UNIX)")]
            jti: Annotated[str, u.Field(description="Token ID")] = ""
            iss: Annotated[
                str,
                u.Field(
                    description="Issuer",
                ),
            ] = "flext-auth"
            aud: Annotated[
                str,
                u.Field(
                    description="Audience",
                ),
            ] = "flext-api"
            session_id: Annotated[str, u.Field(description="Session ID")] = ""

        class TokenRequest(m.Value):
            """Generic token generation request (immutable value object)."""

            identity_id: Annotated[str, u.Field(..., description="Identity ID")]
            token_type: Annotated[
                t.Auth.TokenRequestType,
                u.Field(
                    description="Token type",
                ),
            ] = "access"
            expiry_minutes: Annotated[
                t.PositiveInt,
                u.Field(
                    description="Token expiry",
                ),
            ] = c.Auth.ModelValidation.DEFAULT_TOKEN_EXPIRY_MINUTES
            extra_claims: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Additional claims"
            )
            session_id: Annotated[str, u.Field(description="Session ID")] = ""

        class AuthToken(m.Entity):
            """Generic authentication token entity."""

            identity_id: Annotated[str, u.Field(..., description="Identity ID")]
            token: Annotated[str, u.Field(..., description="Token value", exclude=True)]
            expires_at: Annotated[datetime, u.Field(..., description="Expiration time")]
            token_type: Annotated[
                str,
                u.Field(
                    description="Token type",
                ),
            ] = "bearer"
            session_id: Annotated[str, u.Field(description="Session ID")] = ""
            is_revoked: Annotated[
                bool,
                u.Field(description="Revoked status"),
            ] = False
            refresh_token: Annotated[
                str,
                u.Field(
                    description="Refresh token",
                    exclude=True,
                ),
            ] = ""

            @property
            def user_id(self) -> str:
                """User ID property for protocol compatibility."""
                return self.identity_id

            @property
            def expired(self) -> bool:
                """Check if token is expired."""
                return datetime.now(UTC) > self.expires_at

        # =========================================================================
        # IDENTITY MODELS - Generic identity/user entity
        # =========================================================================

        class AuthIdentityRequest(m.Value):
            """Generic identity creation request (immutable value object)."""

            name: Annotated[
                str,
                u.Field(
                    ...,
                    min_length=c.Auth.Credentials.Username.MIN_LENGTH,
                    max_length=c.Auth.Credentials.Username.MAX_LENGTH,
                    description="Unique identity name",
                ),
            ]
            contact: Annotated[
                t.NonEmptyStr,
                u.Field(
                    ...,
                    pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
                    description="Contact info (email)",
                ),
            ]
            credential: Annotated[
                str,
                u.Field(
                    ...,
                    min_length=c.Auth.Credentials.Password.MIN_LENGTH,
                    description="Credential (password/key)",
                    exclude=True,
                ),
            ]
            full_name: Annotated[str, u.Field(description="Full name")] = ""
            roles: t.StrSequence = u.Field(
                default_factory=lambda: ["user"], description="Roles"
            )

        class AuthIdentity(m.Entity):
            """Generic identity/user entity with minimal fields."""

            # Reference to PasswordUtil for use in methods
            _password_util: type | None = (
                None  # Will be set to Auth.PasswordUtil at class definition time
            )

            name: Annotated[
                str,
                u.Field(
                    ...,
                    min_length=c.Auth.Credentials.Username.MIN_LENGTH,
                    max_length=c.Auth.Credentials.Username.MAX_LENGTH,
                    description="Unique identity name",
                ),
            ]
            contact: Annotated[str, u.Field(..., description="Contact info")]
            credential_hash: Annotated[
                str,
                u.Field(
                    description="Hashed credential",
                    exclude=True,
                ),
            ] = ""
            full_name: Annotated[str, u.Field(description="Full name")] = ""
            is_active: Annotated[bool, u.Field(description="Active status")] = True
            roles: t.StrSequence = u.Field(
                default_factory=lambda: ["user"], description="Roles"
            )
            permissions: t.StrSequence = u.Field(
                default_factory=list, description="Permissions"
            )
            failed_attempts: Annotated[
                t.NonNegativeInt,
                u.Field(description="Failed attempts"),
            ] = 0
            locked_until: datetime = u.Field(
                default_factory=lambda: datetime.min.replace(tzinfo=UTC),
                description="Lock time (datetime.min means not locked)",
            )
            last_access: datetime = u.Field(
                default_factory=lambda: datetime.min.replace(tzinfo=UTC),
                description="Last access (datetime.min means never accessed)",
            )

            # Additional attributes expected by tests
            token: Annotated[
                str,
                u.Field(description="Associated token", exclude=True),
            ] = ""
            session_id: Annotated[str, u.Field(description="Session ID")] = ""

            def locked(self) -> bool:
                """Check if identity is locked."""
                if self.locked_until == datetime.min.replace(tzinfo=UTC):
                    return False
                return datetime.now(UTC) < self.locked_until

            def set_credential(self, credential: str) -> p.Result[bool]:
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
                ) as exc:
                    return r[bool].fail(f"Failed to hash credential: {exc}")

            def verify_credential(self, credential: str) -> p.Result[bool]:
                """Verify a credential against stored hash using bcrypt."""
                try:
                    valid = FlextAuthModels.Auth.PasswordUtil.verify_password(
                        credential,
                        self.credential_hash,
                    )
                    return r[bool].ok(valid)
                except (
                    ValueError,
                    TypeError,
                    KeyError,
                    AttributeError,
                    OSError,
                    RuntimeError,
                    ImportError,
                ) as exc:
                    return r[bool].fail(f"Credential verification failed: {exc}")

            def with_successful_access(self) -> Self:
                """Record successful access (fluent interface)."""
                self.last_access = datetime.now(UTC)
                self.failed_attempts = 0
                self.locked_until = datetime.min.replace(tzinfo=UTC)
                return self

        # =========================================================================
        # SESSION MODELS - Generic session entity
        # =========================================================================

        class Session(m.Entity):
            """Generic session entity."""

            identity_id: Annotated[str, u.Field(..., description="Identity ID")]
            session_token: Annotated[
                str,
                u.Field(..., description="Session token", exclude=True),
            ]
            expires_at: Annotated[datetime, u.Field(..., description="Expiration time")]
            is_active: Annotated[bool, u.Field(description="Active status")] = True
            ip_address: Annotated[str, u.Field(description="IP address")] = ""
            user_agent: Annotated[str, u.Field(description="User agent")] = ""
            last_accessed: datetime = u.Field(
                default_factory=lambda: datetime.now(UTC),
                description="Last access",
            )

            @property
            def expired(self) -> bool:
                """Check if session is expired."""
                return datetime.now(UTC) > self.expires_at

        # =========================================================================
        # ROLE & PERMISSION MODELS - Generic RBAC
        # =========================================================================

        class Role(m.Entity):
            """Generic role entity."""

            name: Annotated[
                t.NonEmptyStr,
                u.Field(
                    ...,
                    max_length=c.Auth.ModelValidation.MAX_ROLE_NAME_LENGTH,
                    description="Role name",
                ),
            ]
            description: Annotated[
                str,
                u.Field(
                    max_length=c.Auth.ModelValidation.MAX_ROLE_DESCRIPTION_LENGTH,
                    description="Description",
                ),
            ] = ""
            permissions: t.StrSequence = u.Field(
                default_factory=list, description="Permissions"
            )

        class Permission(m.Entity):
            """Generic permission entity."""

            name: Annotated[
                t.NonEmptyStr,
                u.Field(
                    ...,
                    max_length=c.Auth.ModelValidation.MAX_PERMISSION_NAME_LENGTH,
                    description="Permission",
                ),
            ]
            description: Annotated[
                str,
                u.Field(
                    max_length=c.Auth.ModelValidation.MAX_PERMISSION_DESCRIPTION_LENGTH,
                    description="Description",
                ),
            ] = ""
            resource: Annotated[str, u.Field(description="Resource path")] = ""
            action: Annotated[str, u.Field(description="Action type")] = ""

        # =========================================================================
        # PROVIDER MODELS - Generic provider configuration
        # =========================================================================

        class ProviderConfig(m.FlexibleModel):
            """Generic provider configuration (immutable value object)."""

            name: Annotated[str, u.Field(..., description="Provider name")]
            type: Annotated[str, u.Field(..., description="Provider type")]
            enabled: Annotated[bool, u.Field(description="Enabled status")] = True

            # Extended configuration fields (migrated from TypedDict)
            # All optional to support various provider types
            provider_type: Annotated[
                str | None, u.Field(description="Authentication provider type")
            ] = None
            secret_key: Annotated[
                str | None, u.Field(description="Provider secret key")
            ] = None
            algorithm: Annotated[
                str | None, u.Field(description="Token signing algorithm")
            ] = None
            token_expiry_minutes: Annotated[
                t.PositiveInt | None, u.Field(description="Token expiry in minutes")
            ] = None
            refresh_expiry_days: Annotated[
                int | None, u.Field(description="Refresh token expiry in days")
            ] = None
            client_id: Annotated[
                str | None, u.Field(description="OAuth client identifier")
            ] = None
            client_secret: Annotated[
                str | None, u.Field(description="OAuth client secret")
            ] = None
            authorization_endpoint: Annotated[
                str | None, u.Field(description="OAuth authorization endpoint URL")
            ] = None
            token_endpoint: Annotated[
                str | None, u.Field(description="OAuth token endpoint URL")
            ] = None
            redirect_uri: Annotated[
                str | None, u.Field(description="OAuth redirect URI")
            ] = None
            scope: Annotated[str | None, u.Field(description="OAuth scope")] = None
            audience: Annotated[
                str | None, u.Field(description="Token audience claim")
            ] = None
            issuer: Annotated[str | None, u.Field(description="Token issuer claim")] = (
                None
            )
            realm: Annotated[str | None, u.Field(description="Kerberos realm")] = None
            kdc_host: Annotated[
                str | None, u.Field(description="Kerberos KDC hostname")
            ] = None
            kdc_port: Annotated[
                t.PortNumber | None, u.Field(description="Kerberos KDC port")
            ] = None
            service_principal: Annotated[
                str | None, u.Field(description="Kerberos service principal")
            ] = None
            keytab_path: Annotated[
                str | None, u.Field(description="Kerberos keytab file path")
            ] = None
            entity_id: Annotated[
                str | None, u.Field(description="SAML entity identifier")
            ] = None
            sso_url: Annotated[
                str | None, u.Field(description="SAML SSO endpoint URL")
            ] = None
            slo_url: Annotated[
                str | None, u.Field(description="SAML SLO endpoint URL")
            ] = None
            x509_cert: Annotated[
                str | None, u.Field(description="SAML X.509 certificate")
            ] = None
            ldap_url: Annotated[str | None, u.Field(description="LDAP server URL")] = (
                None
            )
            bind_dn: Annotated[
                str | None, u.Field(description="LDAP bind distinguished name")
            ] = None
            base_dn: Annotated[
                str | None, u.Field(description="LDAP base distinguished name")
            ] = None
            search_filter: Annotated[
                str | None, u.Field(description="LDAP search filter")
            ] = None
            flow: Annotated[str | None, u.Field(description="OAuth flow type")] = None
            use_pkce: Annotated[
                bool | None, u.Field(description="Enable PKCE for OAuth")
            ] = None
            token_endpoint_auth_method: Annotated[
                str | None, u.Field(description="Token endpoint authentication method")
            ] = None

            def __contains__(self, key: str) -> bool:
                """Dict-like containment check."""
                return key in self.__class__.model_fields

            @property
            def configured(self) -> bool:
                """Check if configured."""
                return bool(self.name and self.type)

        class ProviderConfiguration(m.FlexibleModel):
            """Provider configuration for authentication providers."""

            name: Annotated[str, u.Field(description="Provider name")] = "default"
            version: Annotated[str, u.Field(description="Provider version")] = "1.0.0"
            capabilities: t.StrSequence = u.Field(
                default_factory=list, description="Provider capabilities"
            )

        class ApiKeyValidation(m.Value):
            """API key validation request (immutable value object)."""

            api_key: Annotated[str, u.Field(..., description="API key to validate")]
            metadata: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Additional validation data"
            )

        class ApiKeyData(m.Value):
            """API key data structure (immutable value object)."""

            key_hash: Annotated[str, u.Field(..., description="Hashed API key")]
            name: Annotated[str, u.Field(..., description="Key name")]
            permissions: t.StrSequence = u.Field(
                default_factory=list, description="Key permissions"
            )
            is_active: Annotated[bool, u.Field(description="Key active status")] = True
            expires_at: datetime = u.Field(
                default_factory=lambda: datetime.max.replace(tzinfo=UTC),
                description="Key expiration (datetime.max means never expires)",
            )
            created_at: datetime = u.Field(
                default_factory=lambda: datetime.now(UTC),
                description="Creation time",
            )

        class CredentialValidation(m.Value):
            """Credential validation request (immutable value object)."""

            username: Annotated[str, u.Field(..., description="Username")]
            password: Annotated[str, u.Field(..., description="Password", exclude=True)]
            metadata: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Additional validation data"
            )

        # =========================================================================
        # CREDENTIAL MODELS - Generic credential handling
        # =========================================================================

        class Credential(m.Value):
            """Generic credential container (immutable value object)."""

            credential_type: Annotated[str, u.Field(..., description="Credential type")]
            value: Annotated[
                str,
                u.Field(..., description="Credential value", exclude=True),
            ]
            metadata: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Additional data"
            )

        # =========================================================================
        # AUTHENTICATION RESPONSE - Generic response
        # =========================================================================

        class AuthResponse(m.Value):
            """Generic authentication response (immutable value object)."""

            success: Annotated[bool, u.Field(..., description="Authentication success")]
            identity: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Identity data"
            )
            token: Annotated[str, u.Field(description="Token", exclude=True)] = ""
            message: Annotated[str, u.Field(description="Response message")] = ""
            metadata: t.RecursiveContainerMapping = u.Field(
                default_factory=dict, description="Additional data"
            )

        # =========================================================================
        # OAUTH2 TOKEN RESPONSE - OAuth2 token exchange result
        # =========================================================================

        class OAuth2TokenResponse(m.Value):
            """OAuth2 token response from token endpoint."""

            access_token: Annotated[str, u.Field(..., description="Access token")]
            token_type: Annotated[
                str,
                u.Field(description="Token type"),
            ] = "Bearer"
            expires_in: Annotated[
                t.NonNegativeInt,
                u.Field(description="Expiry seconds"),
            ] = 3600
            scope: Annotated[str, u.Field(description="Granted scope")] = ""
            refresh_token: Annotated[
                str,
                u.Field(
                    description="Refresh token",
                    exclude=True,
                ),
            ] = ""

        # =========================================================================
        # KERBEROS TICKET DATA - Kerberos ticket information
        # =========================================================================

        class KerberosTicketData(m.Value):
            """Kerberos ticket information."""

            ticket: Annotated[str, u.Field(..., description="Kerberos ticket")]
            principal: Annotated[
                str,
                u.Field(description="Kerberos principal"),
            ] = ""
            realm: Annotated[str, u.Field(description="Kerberos realm")] = ""

        # =========================================================================
        # HTTP RESPONSE DATA - Generic HTTP response container
        # =========================================================================

        class HttpResponseData(m.Value):
            """Generic HTTP response data."""

            status_code: Annotated[
                t.HttpStatusCode,
                u.Field(..., description="HTTP status code"),
            ]
            body: Annotated[str, u.Field(description="Response body")] = ""
            headers: t.StrMapping = u.Field(
                default_factory=dict, description="Response headers"
            )

        # =========================================================================
        # PROVIDERS NAMESPACE - Provider metadata and related models
        # =========================================================================

        # =========================================================================
        # REGISTRY WRAPPER MODELS - Internal registry wrappers
        # =========================================================================

        class ProviderWrapper(m.Value):
            """Wrapper for auth provider instances."""

            model_config: ClassVar[m.ConfigDict] = m.ConfigDict(
                arbitrary_types_allowed=True,
            )

            category: Annotated[str, u.Field(description="Provider category")]
            provider: Annotated[
                p.Auth.FlextAuthBaseProvider,
                u.Field(description="Provider instance"),
            ]

        class ConfigWrapper(m.Value):
            """Protocol-conformant wrapper for settings data."""

            category: Annotated[str, u.Field(description="Config category")]
            data: Annotated[t.ConfigurationMapping, u.Field(description="Config data")]

        class MetadataWrapper(m.Value):
            """Protocol-conformant wrapper for metadata."""

            category: Annotated[str, u.Field(description="Metadata category")]
            data: Annotated[m.Value, u.Field(description="Metadata")]

        class Providers:
            """Provider-related models namespace."""

            class Metadata(m.Value):
                """Provider metadata for registry."""

                name: Annotated[str, u.Field(..., description="Provider name")]
                version: Annotated[
                    str,
                    u.Field(description="Provider version"),
                ] = "1.0.0"
                capabilities: tuple[str, ...] = u.Field(
                    default_factory=tuple, description="Provider capabilities"
                )
                extras: t.RecursiveContainerMapping = u.Field(
                    default_factory=dict, description="Extra metadata"
                )

            class Registration(m.Value):
                """Provider registration payload (immutable value object)."""

                name: Annotated[str, u.Field(..., description="Provider name")]
                provider_type: Annotated[
                    str,
                    u.Field(..., description="Provider type"),
                ]


# Short aliases
m = FlextAuthModels

__all__: list[str] = ["FlextAuthModels", "m"]

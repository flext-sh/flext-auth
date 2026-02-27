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
from typing import Literal, Self

import bcrypt
from flext_auth.constants import c
from flext_core import FlextModels, r
from flext_core.typings import t
from pydantic import ConfigDict, Field


class FlextAuthModels(FlextModels):
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

        class ValidationResult(FlextModels.Value):
            """Generic validation result for any operation (immutable value object)."""

            is_valid: bool = Field(..., description="Validation outcome")
            data: dict[str, t.JsonValue] = Field(
                default_factory=dict, description="Result data"
            )
            error: str = Field(default="", description="Error message")
            metadata: dict[str, t.JsonValue] = Field(
                default_factory=dict,
                description="Additional metadata",
            )

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

        class TokenPayload(FlextModels.Value):
            """Generic JWT token payload (immutable value object)."""

            sub: str = Field(..., description="Subject (identity ID)")
            exp: int = Field(..., description="Expiration timestamp (UNIX)")
            iat: int = Field(..., description="Issued at timestamp (UNIX)")
            jti: str = Field(default="", description="Token ID")
            iss: str = Field(
                default="flext-auth",
                description="Issuer",
            )
            aud: str = Field(
                default="flext-api",
                description="Audience",
            )
            session_id: str = Field(default="", description="Session ID")

        class TokenRequest(FlextModels.Value):
            """Generic token generation request (immutable value object)."""

            identity_id: str = Field(..., description="Identity ID")
            token_type: Literal["access", "refresh", "id", "bearer"] = Field(
                default="access",
                description="Token type",
            )
            expiry_minutes: int = Field(
                default=c.Auth.ModelValidation.DEFAULT_TOKEN_EXPIRY_MINUTES,
                ge=1,
                description="Token expiry",
            )
            extra_claims: dict[str, t.JsonValue] = Field(
                default_factory=dict,
                description="Additional claims",
            )
            session_id: str = Field(default="", description="Session ID")

        class AuthToken(FlextModels.Entity):
            """Generic authentication token entity."""

            identity_id: str = Field(..., description="Identity ID")
            token: str = Field(..., description="Token value", exclude=True)

            @property
            def user_id(self) -> str:
                """User ID property for protocol compatibility."""
                return self.identity_id

            token_type: str = Field(
                default="bearer",
                description="Token type",
            )
            expires_at: datetime = Field(..., description="Expiration time")
            session_id: str = Field(default="", description="Session ID")
            is_revoked: bool = Field(default=False, description="Revoked status")
            refresh_token: str = Field(
                default="",
                description="Refresh token",
                exclude=True,
            )

            @property
            def is_expired(self) -> bool:
                """Check if token is expired."""
                return datetime.now(UTC) > self.expires_at

        # =========================================================================
        # IDENTITY MODELS - Generic identity/user entity
        # =========================================================================

        class AuthIdentityRequest(FlextModels.Value):
            """Generic identity creation request (immutable value object)."""

            name: str = Field(
                ...,
                min_length=c.Auth.Credentials.Username.MIN_LENGTH,
                max_length=c.Auth.Credentials.Username.MAX_LENGTH,
                description="Unique identity name",
            )
            contact: str = Field(
                ...,
                min_length=1,
                pattern=r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$",
                description="Contact info (email)",
            )
            credential: str = Field(
                ...,
                min_length=c.Auth.Credentials.Password.MIN_LENGTH,
                description="Credential (password/key)",
                exclude=True,
            )
            full_name: str = Field(default="", description="Full name")
            roles: list[str] = Field(
                default_factory=lambda: ["user"],
                description="Roles",
            )

        class AuthIdentity(FlextModels.Entity):
            """Generic identity/user entity with minimal fields."""

            # Reference to PasswordUtil for use in methods
            _password_util: type | None = (
                None  # Will be set to Auth.PasswordUtil at class definition time
            )

            name: str = Field(
                ...,
                min_length=c.Auth.Credentials.Username.MIN_LENGTH,
                max_length=c.Auth.Credentials.Username.MAX_LENGTH,
                description="Unique identity name",
            )
            contact: str = Field(..., description="Contact info")
            credential_hash: str = Field(
                default="",
                description="Hashed credential",
                exclude=True,
            )
            full_name: str = Field(default="", description="Full name")
            is_active: bool = Field(default=True, description="Active status")
            roles: list[str] = Field(
                default_factory=lambda: ["user"],
                description="Roles",
            )
            permissions: list[str] = Field(
                default_factory=list, description="Permissions"
            )
            failed_attempts: int = Field(default=0, ge=0, description="Failed attempts")
            locked_until: datetime = Field(
                default_factory=lambda: datetime.min.replace(tzinfo=UTC),
                description="Lock time (datetime.min means not locked)",
            )
            last_access: datetime = Field(
                default_factory=lambda: datetime.min.replace(tzinfo=UTC),
                description="Last access (datetime.min means never accessed)",
            )

            # Backward compatibility aliases for User model expectations
            @property
            def id(self) -> str:
                """Alias for unique_id to support id expectations."""
                return self.unique_id

            @property
            def user_id(self) -> str:
                """Alias for id to support user_id expectations."""
                return self.id

            @property
            def username(self) -> str:
                """Alias for name to support username expectations."""
                return self.name

            @property
            def email(self) -> str:
                """Alias for contact to support email expectations."""
                return self.contact

            # Additional attributes expected by tests
            token: str = Field(default="", description="Associated token", exclude=True)
            session_id: str = Field(default="", description="Session ID")

            def __getitem__(self, key: str) -> t.GeneralValueType:
                """Support dictionary-like access for backward compatibility."""
                if key == "user":
                    return {"id": self.id, "username": self.name, "email": self.contact}
                if key == "session":
                    return {"id": self.session_id} if self.session_id else {"id": ""}
                if key == "jwt_token":
                    return self.token
                # Direct attribute access for safe attributes only
                if key == "id":
                    return self.id
                if key == "name":
                    return self.name
                if key == "contact":
                    return self.contact
                if key == "token":
                    return self.token
                if key == "session_id":
                    return self.session_id
                if key == "last_access":
                    return self.last_access
                if key == "failed_attempts":
                    return self.failed_attempts
                if key == "locked_until":
                    return self.locked_until
                msg = f"Attribute '{key}' not accessible via __getitem__"
                raise KeyError(msg)

            def with_successful_access(self) -> Self:
                """Record successful access (fluent interface)."""
                self.last_access = datetime.now(UTC)
                self.failed_attempts = 0
                self.locked_until = datetime.min.replace(tzinfo=UTC)
                return self

            def is_locked(self) -> bool:
                """Check if identity is locked."""
                if self.locked_until == datetime.min.replace(tzinfo=UTC):
                    return False
                return datetime.now(UTC) < self.locked_until

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

        # =========================================================================
        # SESSION MODELS - Generic session entity
        # =========================================================================

        class Session(FlextModels.Entity):
            """Generic session entity."""

            identity_id: str = Field(..., description="Identity ID")
            session_token: str = Field(..., description="Session token", exclude=True)
            expires_at: datetime = Field(..., description="Expiration time")
            is_active: bool = Field(default=True, description="Active status")
            ip_address: str = Field(default="", description="IP address")
            user_agent: str = Field(default="", description="User agent")
            last_accessed: datetime = Field(
                default_factory=lambda: datetime.now(UTC),
                description="Last access",
            )

            @property
            def is_expired(self) -> bool:
                """Check if session is expired."""
                return datetime.now(UTC) > self.expires_at

        # =========================================================================
        # ROLE & PERMISSION MODELS - Generic RBAC
        # =========================================================================

        class Role(FlextModels.Entity):
            """Generic role entity."""

            name: str = Field(
                ...,
                min_length=1,
                max_length=c.Auth.ModelValidation.MAX_ROLE_NAME_LENGTH,
                description="Role name",
            )
            description: str = Field(
                default="",
                max_length=c.Auth.ModelValidation.MAX_ROLE_DESCRIPTION_LENGTH,
                description="Description",
            )
            permissions: list[str] = Field(
                default_factory=list, description="Permissions"
            )

        class Permission(FlextModels.Entity):
            """Generic permission entity."""

            name: str = Field(
                ...,
                min_length=1,
                max_length=c.Auth.ModelValidation.MAX_PERMISSION_NAME_LENGTH,
                description="Permission",
            )
            description: str = Field(
                default="",
                max_length=c.Auth.ModelValidation.MAX_PERMISSION_DESCRIPTION_LENGTH,
                description="Description",
            )
            resource: str = Field(default="", description="Resource path")
            action: str = Field(default="", description="Action type")

        # =========================================================================
        # PROVIDER MODELS - Generic provider configuration
        # =========================================================================

        class ProviderConfig(FlextModels.Value):
            """Generic provider configuration (immutable value object)."""

            model_config = ConfigDict(extra="allow")

            name: str = Field(..., description="Provider name")
            type: str = Field(..., description="Provider type")
            enabled: bool = Field(default=True, description="Enabled status")

            # Extended configuration fields (migrated from TypedDict)
            # All optional to support various provider types
            provider_type: str | None = None
            secret_key: str | None = None
            algorithm: str | None = None
            token_expiry_minutes: int | None = None
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
            kdc_port: int | None = None
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

            @property
            def is_configured(self) -> bool:
                """Check if configured."""
                return bool(self.name and self.type)

            def get(
                self, key: str, default: t.GeneralValueType = None
            ) -> t.GeneralValueType:
                """Dict-like get method for backward compatibility."""
                return (
                    self.__dict__.get(key, default) if hasattr(self, key) else default
                )

            def __contains__(self, key: str) -> bool:
                """Dict-like containment check."""
                return key in self.__class__.model_fields

            def __getitem__(self, key: str) -> t.GeneralValueType:
                """Dict-like access."""
                return self.__dict__.get(key) if hasattr(self, key) else None

        class ProviderConfiguration(UserDict[str, t.GeneralValueType]):
            """Provider configuration for authentication providers."""

            def __init__(
                self,
                dict_: Mapping[str, t.JsonValue] | None = None,
                /,
                **kwargs: t.GeneralValueType,
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
                    self["capabilities"] = []

        class ApiKeyValidation(FlextModels.Value):
            """API key validation request (immutable value object)."""

            api_key: str = Field(..., description="API key to validate")
            metadata: dict[str, t.JsonValue] = Field(
                default_factory=dict,
                description="Additional validation data",
            )

        class ApiKeyData(FlextModels.Value):
            """API key data structure (immutable value object)."""

            key_hash: str = Field(..., description="Hashed API key")
            name: str = Field(..., description="Key name")
            permissions: list[str] = Field(
                default_factory=list,
                description="Key permissions",
            )
            is_active: bool = Field(default=True, description="Key active status")
            expires_at: datetime = Field(
                default_factory=lambda: datetime.max.replace(tzinfo=UTC),
                description="Key expiration (datetime.max means never expires)",
            )
            created_at: datetime = Field(
                default_factory=lambda: datetime.now(UTC),
                description="Creation time",
            )

        class CredentialValidation(FlextModels.Value):
            """Credential validation request (immutable value object)."""

            username: str = Field(..., description="Username")
            password: str = Field(..., description="Password", exclude=True)
            metadata: dict[str, t.JsonValue] = Field(
                default_factory=dict,
                description="Additional validation data",
            )

        # =========================================================================
        # CREDENTIAL MODELS - Generic credential handling
        # =========================================================================

        class Credential(FlextModels.Value):
            """Generic credential container (immutable value object)."""

            credential_type: str = Field(..., description="Credential type")
            value: str = Field(..., description="Credential value", exclude=True)
            metadata: dict[str, t.JsonValue] = Field(
                default_factory=dict,
                description="Additional data",
            )

        # =========================================================================
        # AUTHENTICATION RESPONSE - Generic response
        # =========================================================================

        class AuthResponse(FlextModels.Value):
            """Generic authentication response (immutable value object)."""

            success: bool = Field(..., description="Authentication success")
            identity: dict[str, t.JsonValue] = Field(
                default_factory=dict,
                description="Identity data",
            )
            token: str = Field(default="", description="Token", exclude=True)
            message: str = Field(default="", description="Response message")
            metadata: dict[str, t.JsonValue] = Field(
                default_factory=dict,
                description="Additional data",
            )


# Forward references resolved via from __future__ import annotations at module top
# This architectural approach avoids runtime model_rebuild() calls

# Short aliases
m = FlextAuthModels

__all__ = ["FlextAuthModels", "m"]

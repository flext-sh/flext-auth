"""FLEXT Auth Models - Single generic class with consolidated Pydantic models.

Uses Python 3.13+ syntax, generic patterns, and SOLID principles for all
authentication domain models. One FlextAuthModels class with nested models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import UserDict
from datetime import UTC, datetime
from typing import Self

# Import password utilities directly
import bcrypt

# FLEXT Standard imports
from flext_core import (
    FlextModels as m,
    FlextResult as r,
)
from pydantic import ConfigDict, Field, computed_field, model_validator


class PasswordUtil:
    """Password utilities for authentication."""

    @staticmethod
    def hash_password(password: str) -> str:
        """Hash a password using bcrypt."""
        salt = bcrypt.gensalt(rounds=12)
        return bcrypt.hashpw(password.encode(), salt).decode()

    @staticmethod
    def verify_password(password: str, hashed: str) -> bool:
        """Verify a password against its hash."""
        return bcrypt.checkpw(password.encode(), hashed.encode())


class FlextAuthModels(m):
    """Single generic authentication models class with nested Pydantic models.

    All authentication domain models consolidated with validation, composition,
    and SOLID principles. Uses Python 3.13+ syntax and flext-core patterns.
    """

    def __init_subclass__(cls, **kwargs: object) -> None:
        """Warn when FlextAuthModels is subclassed directly."""
        super().__init_subclass__(**kwargs)
        flext_u.Deprecation.warn_once(
            f"subclass:{cls.__name__}",
            "Subclassing FlextAuthModels is deprecated. Use FlextModels directly instead.",
        )

    # =========================================================================
    # GENERIC VALIDATION RESULT - Single model for all validations
    # =========================================================================

    class ValidationResult(m.Value):
        """Generic validation result for any operation (immutable value object)."""

        is_valid: bool = Field(..., description="Validation outcome")
        data: dict[str, object] = Field(default_factory=dict, description="Result data")
        error: str = Field(default="", description="Error message")
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Additional metadata",
        )

        @computed_field
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

    class TokenPayload(m.Value):
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

    class TokenRequest(m.Value):
        """Generic token generation request (immutable value object)."""

        identity_id: str = Field(..., description="Identity ID")
        token_type: str = Field(
            default="access",
            description="Token type",
        )
        expiry_minutes: int = Field(
            default=60,
            ge=1,
            description="Token expiry",
        )
        extra_claims: dict[str, object] = Field(
            default_factory=dict,
            description="Additional claims",
        )
        session_id: str = Field(default="", description="Session ID")

        @model_validator(mode="after")
        def validate_token_type(self) -> Self:
            """Validate token type."""
            valid_types = {"access", "refresh", "id", "bearer"}
            if self.token_type not in valid_types:
                msg = f"Token type must be one of {valid_types}"
                raise ValueError(msg)
            return self

    class AuthToken(m.Entity):
        """Generic authentication token entity."""

        identity_id: str = Field(..., description="Identity ID")
        token: str = Field(..., description="Token value", exclude=True)
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

        @computed_field
        @property
        def is_expired(self) -> bool:
            """Check if token is expired."""
            return datetime.now(UTC) > self.expires_at

    # =========================================================================
    # IDENTITY MODELS - Generic identity/user entity
    # =========================================================================

    class IdentityRequest(m.Value):
        """Generic identity creation request (immutable value object)."""

        name: str = Field(
            ...,
            min_length=3,
            max_length=100,
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
            min_length=8,
            description="Credential (password/key)",
            exclude=True,
        )
        full_name: str = Field(default="", description="Full name")
        roles: list[str] = Field(
            default_factory=lambda: ["user"],
            description="Roles",
        )

    class Identity(m.Entity):
        """Generic identity/user entity with minimal fields."""

        name: str = Field(
            ...,
            min_length=3,
            max_length=100,
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
        permissions: list[str] = Field(default_factory=list, description="Permissions")
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

        def __getitem__(self, key: str) -> object:
            """Support dictionary-like access for backward compatibility."""
            if key == "user":
                return {"id": self.id, "username": self.name, "email": self.contact}
            if key == "session":
                return {"id": self.session_id} if self.session_id else {"id": ""}
            if key == "jwt_token":
                return self.token
            return getattr(self, key)

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
                is_valid = PasswordUtil.verify_password(
                    credential,
                    self.credential_hash,
                )
                return r[bool].ok(is_valid)
            except Exception as e:
                return r[bool].fail(f"Credential verification failed: {e}")

        def set_credential(self, credential: str) -> r[bool]:
            """Set a new credential with bcrypt hashing."""
            try:
                self.credential_hash = PasswordUtil.hash_password(credential)
                return r[bool].ok(True)
            except Exception as e:
                return r[bool].fail(f"Failed to hash credential: {e}")

    # Backward compatibility alias for tests expecting User model
    User = Identity

    # =========================================================================
    # SESSION MODELS - Generic session entity
    # =========================================================================

    class Session(m.Entity):
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

        @computed_field
        @property
        def is_expired(self) -> bool:
            """Check if session is expired."""
            return datetime.now(UTC) > self.expires_at

    # =========================================================================
    # ROLE & PERMISSION MODELS - Generic RBAC
    # =========================================================================

    class Role(m.Entity):
        """Generic role entity."""

        name: str = Field(..., min_length=1, max_length=50, description="Role name")
        description: str = Field(default="", max_length=500, description="Description")
        permissions: list[str] = Field(default_factory=list, description="Permissions")

    class Permission(m.Entity):
        """Generic permission entity."""

        name: str = Field(..., min_length=1, max_length=100, description="Permission")
        description: str = Field(default="", max_length=500, description="Description")
        resource: str = Field(default="", description="Resource path")
        action: str = Field(default="", description="Action type")

    # =========================================================================
    # PROVIDER MODELS - Generic provider configuration
    # =========================================================================

    class ProviderConfig(m.Value):
        """Generic provider configuration (immutable value object)."""

        model_config = ConfigDict(extra="allow")

        name: str = Field(..., description="Provider name")
        type: str = Field(..., description="Provider type")
        enabled: bool = Field(default=True, description="Enabled status")

        @computed_field
        @property
        def is_configured(self) -> bool:
            """Check if configured."""
            return bool(self.name and self.type)

    class ProviderConfiguration(UserDict[str, object]):
        """Provider configuration for authentication providers."""

        def __init__(
            self,
            dict_: dict[str, object] | None = None,
            /,
            **kwargs: object,
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

    class ApiKeyValidation(m.Value):
        """API key validation request (immutable value object)."""

        api_key: str = Field(..., description="API key to validate")
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Additional validation data",
        )

    class ApiKeyData(m.Value):
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

    class CredentialValidation(m.Value):
        """Credential validation request (immutable value object)."""

        username: str = Field(..., description="Username")
        password: str = Field(..., description="Password", exclude=True)
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Additional validation data",
        )

    # =========================================================================
    # CREDENTIAL MODELS - Generic credential handling
    # =========================================================================

    class Credential(m.Value):
        """Generic credential container (immutable value object)."""

        credential_type: str = Field(..., description="Credential type")
        value: str = Field(..., description="Credential value", exclude=True)
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Additional data",
        )

    # =========================================================================
    # AUTHENTICATION RESPONSE - Generic response
    # =========================================================================

    class AuthResponse(m.Value):
        """Generic authentication response (immutable value object)."""

        success: bool = Field(..., description="Authentication success")
        identity: object = Field(
            default_factory=dict,
            description="Identity data",
        )
        token: str = Field(default="", description="Token", exclude=True)
        message: str = Field(default="", description="Response message")
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Additional data",
        )


# Short aliases
m = FlextAuthModels
m_auth = FlextAuthModels

__all__ = ["FlextAuthModels", "m", "m_auth"]

"""FLEXT Auth Models - Single generic class with consolidated Pydantic models.

Uses Python 3.13+ syntax, generic patterns, and SOLID principles for all
authentication domain models. One FlextAuthModels class with nested models.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections import UserDict
from datetime import UTC, datetime
from typing import ClassVar, Self

from flext_core import m as m_core, r
from pydantic import Field, computed_field, model_validator

from flext_auth.constants import FlextAuthConstants

# FlextAuthUtilities imported lazily to avoid circular dependency


class FlextAuthModels(m_core):
    """Single generic authentication models class with nested Pydantic models.

    All authentication domain models consolidated with validation, composition,
    and SOLID principles. Uses Python 3.13+ syntax and flext-core patterns.
    """

    # =========================================================================
    # GENERIC VALIDATION RESULT - Single model for all validations
    # =========================================================================

    class ValidationResult(m_core.Value):
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

    class TokenPayload(m_core.Value):
        """Generic JWT token payload (immutable value object)."""

        sub: str = Field(..., description="Subject (identity ID)")
        exp: int = Field(..., description="Expiration timestamp (UNIX)")
        iat: int = Field(..., description="Issued at timestamp (UNIX)")
        jti: str = Field(default="", description="Token ID")
        iss: str = Field(
            default=FlextAuthConstants.Auth.DEFAULT_ISSUER,
            description="Issuer",
        )
        aud: str = Field(
            default=FlextAuthConstants.Auth.DEFAULT_AUDIENCE,
            description="Audience",
        )
        session_id: str = Field(default="", description="Session ID")

    class TokenRequest(m_core.Value):
        """Generic token generation request (immutable value object)."""

        identity_id: str = Field(..., description="Identity ID")
        token_type: FlextAuthConstants.Auth.TokenTypeLiteral | str = Field(
            default=FlextAuthConstants.Auth.TokenTypes.ACCESS.value,
            description="Token type",
        )
        expiry_minutes: int = Field(
            default=FlextAuthConstants.Auth.DEFAULT_JWT_EXPIRY_MINUTES,
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

    class AuthToken(m_core.Entity):
        """Generic authentication token entity."""

        identity_id: str = Field(..., description="Identity ID")
        token: str = Field(..., description="Token value", exclude=True)
        token_type: str = Field(
            default=FlextAuthConstants.Auth.TokenTypes.BEARER.value,
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

    class IdentityRequest(m_core.Value):
        """Generic identity creation request (immutable value object)."""

        name: str = Field(
            ...,
            min_length=3,
            max_length=FlextAuthConstants.Auth.MAX_USERNAME_LENGTH,
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
            min_length=FlextAuthConstants.Auth.CREDENTIAL_MIN_LENGTH,
            description="Credential (password/key)",
            exclude=True,
        )
        full_name: str = Field(default="", description="Full name")
        roles: list[str] = Field(
            default_factory=lambda: [FlextAuthConstants.Auth.RoleTypes.USER.value],
            description="Roles",
        )

    class Identity(m_core.Entity):
        """Generic identity/user entity with minimal fields."""

        name: str = Field(
            ...,
            min_length=3,
            max_length=FlextAuthConstants.Auth.MAX_USERNAME_LENGTH,
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
            default_factory=lambda: [FlextAuthConstants.Auth.RoleTypes.USER.value],
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
            from flext_auth.utilities import (
                FlextAuthUtilities,  # Lazy import
            )

            return FlextAuthUtilities.verify_credential(
                credential,
                self.credential_hash,
            )

        def set_credential(self, credential: str) -> r[bool]:
            """Set a new credential with bcrypt hashing."""
            from flext_auth.utilities import (
                FlextAuthUtilities,  # Lazy import
            )

            hash_result = FlextAuthUtilities.hash_credential(credential)
            if hash_result.is_success:
                self.credential_hash = hash_result.unwrap()
                return r[bool].ok(True)
            return r[bool].fail(f"Failed to hash credential: {hash_result.error}")

    # Backward compatibility alias for tests expecting User model
    User = Identity

    # =========================================================================
    # SESSION MODELS - Generic session entity
    # =========================================================================

    class Session(m_core.Entity):
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

    class Role(m_core.Entity):
        """Generic role entity."""

        name: str = Field(..., min_length=1, max_length=50, description="Role name")
        description: str = Field(default="", max_length=500, description="Description")
        permissions: list[str] = Field(default_factory=list, description="Permissions")

    class Permission(m_core.Entity):
        """Generic permission entity."""

        name: str = Field(..., min_length=1, max_length=100, description="Permission")
        description: str = Field(default="", max_length=500, description="Description")
        resource: str = Field(default="", description="Resource path")
        action: str = Field(default="", description="Action type")

    # =========================================================================
    # PROVIDER MODELS - Generic provider configuration
    # =========================================================================

    class ProviderConfig(m_core.Value):
        """Generic provider configuration (immutable value object)."""

        model_config: ClassVar[dict[str, str]] = {"extra": "allow"}

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

    class ApiKeyValidation(m_core.Value):
        """API key validation request (immutable value object)."""

        api_key: str = Field(..., description="API key to validate")
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Additional validation data",
        )

    class ApiKeyData(m_core.Value):
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

    class CredentialValidation(m_core.Value):
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

    class Credential(m_core.Value):
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

    class AuthResponse(m_core.Value):
        """Generic authentication response (immutable value object)."""

        success: bool = Field(..., description="Authentication success")
        identity: FlextAuthModels.Identity = Field(
            default_factory=lambda: FlextAuthModels.Identity(
                unique_id="",
                name="",
                contact="",
            ),
            description="Identity data",
        )
        token: str = Field(default="", description="Token", exclude=True)
        message: str = Field(default="", description="Response message")
        metadata: dict[str, object] = Field(
            default_factory=dict,
            description="Additional data",
        )


m = FlextAuthModels  # Runtime alias (not TypeAlias to avoid PYI042)


# =============================================================================
# CREATE AND POPULATE FlextModels.Auth NAMESPACE
# =============================================================================
# Create namespace if it doesn't exist (no empty class in flext-core)
# Use lazy import to avoid circular dependency
def _populate_auth_namespace() -> None:
    """Populate FlextModels.Auth namespace dynamically."""
    from flext_core import (
        FlextModels,  # Lazy import to avoid circular dependency
    )

    if not hasattr(FlextModels, "Auth"):

        class Auth:
            """Auth project namespace - populated by flext-auth.

            This namespace contains all Auth-specific models from flext-auth.
            Access via: FlextModels.Auth.ValidationResult, FlextModels.Auth.TokenPayload, etc.
            Populated by: flext-auth/src/flext_auth/models.py
            """

        FlextModels.Auth = Auth  # type: ignore[assignment]  # Dynamic namespace creation

    # Get all attributes from FlextAuthModels that are models, classes, or type aliases
    # Exclude private attributes and special methods
    auth_model_attrs = {
        name: attr
        for name, attr in vars(FlextAuthModels).items()
        if not name.startswith("_")
        and (
            isinstance(attr, type)
            or hasattr(attr, "__origin__")  # TypeAlias
            or (callable(attr) and not isinstance(attr, type(FlextAuthModels.__init__)))
        )
    }

    # Populate FlextModels.Auth namespace with direct declarations
    for name, attr in auth_model_attrs.items():
        setattr(FlextModels.Auth, name, attr)  # type: ignore[attr-defined]  # Dynamic namespace population


_populate_auth_namespace()

__all__ = ["FlextAuthModels", "m"]

"""FLEXT Auth Models - Generic pydantic models with flext-core integration.

Uses Python 3.13+ syntax, railway-oriented programming, and consolidated generic patterns
for maximum maintainability. Single FlextAuthModels class with SOLID principles.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Self

from flext_core import FlextModels, FlextResult
from pydantic import BaseModel, Field

from flext_auth.constants import FlextAuthConstants


class FlextAuthModels(FlextModels):
    """Generic auth models using flext-core patterns and Python 3.13+ features.

    Minimal line count through consolidated patterns, railway-oriented operations.
    Domain-agnostic models for any authentication system.
    """

    # Generic type aliases for minimal field definitions
    type IdentityIdField = str | None
    type TimestampField = datetime | None
    type RolesField = list[str]
    type PermissionsField = list[str]
    type TokenField = str
    type BoolField = bool
    type IntField = int

    # =========================================================================
    # CONSOLIDATED GENERIC MODELS
    # =========================================================================

    class TokenPayload(BaseModel):
        """Generic token payload with consolidated field definitions."""

        sub: str = Field(..., description="Subject (identity ID)")
        exp: int = Field(..., description="Expiration timestamp")
        iat: int = Field(..., description="Issued at timestamp")
        jti: str | None = Field(default=None, description="Token ID")
        iss: str | None = Field(default=None, description="Issuer")
        aud: str | None = Field(default=None, description="Audience")
        session_id: str | None = Field(default=None, description="Session ID")

    class StatusResponse(BaseModel):
        """Generic service status response with default factories."""

        status: str = Field(..., description="Operational status")
        service: str = Field(..., description="Service name")
        capabilities: list[str] = Field(
            default_factory=list, description="Capabilities"
        )
        version: str | None = Field(default=None, description="Version")
        timestamp: datetime = Field(
            default_factory=lambda: datetime.now(UTC), description="Report timestamp"
        )

    # =========================================================================
    # GENERIC IDENTITY MODELS - DOMAIN AGNOSTIC
    # =========================================================================

    class IdentityCreationRequest(BaseModel):
        """Generic identity creation with consolidated field validation."""

        name: str = Field(
            ...,
            min_length=FlextAuthConstants.IDENTITY_MIN_LENGTH,
            max_length=FlextAuthConstants.IDENTITY_MAX_LENGTH,
            description="Unique identity name",
        )
        contact: str = Field(..., description="Contact information")
        credential: str = Field(
            ...,
            min_length=FlextAuthConstants.CREDENTIAL_MIN_LENGTH,
            description="Credential",
            exclude=True,
        )
        full_name: str | None = Field(default=None, description="Full name")
        roles: RolesField = Field(
            default_factory=lambda: FlextAuthConstants.DEFAULT_ROLES,
            description="Roles",
        )

    class Identity(FlextModels.Entity):
        """Generic identity model with railway-oriented operations."""

        # Consolidated field definitions using type aliases
        identity_id: IdentityIdField = Field(
            default=None, description="Unique identifier"
        )
        name: str = Field(
            ...,
            min_length=FlextAuthConstants.IDENTITY_MIN_LENGTH,
            max_length=FlextAuthConstants.IDENTITY_MAX_LENGTH,
            description="Unique identity name",
        )
        contact: str = Field(..., description="Contact information")
        credential_hash: str = Field(
            default="", description="Hashed credential", exclude=True
        )
        failed_attempts: IntField = Field(
            default=0, description="Failed attempts", ge=0
        )
        locked_until: TimestampField = Field(
            default=None, description="Lock expiration"
        )
        full_name: str | None = Field(default=None, description="Full name")
        is_active: BoolField = Field(default=True, description="Active status")
        roles: RolesField = Field(default_factory=list, description="Roles")
        permissions: PermissionsField = Field(
            default_factory=list, description="Permissions"
        )
        last_access: TimestampField = Field(default=None, description="Last access")

        # Railway-oriented credential operations
        def record_successful_access(self) -> Self:
            """Fluent interface for successful access recording."""
            self.last_access = datetime.now(UTC)
            self.failed_attempts = 0
            self.locked_until = None
            return self

        def verify_credential(self, credential: str) -> FlextResult[bool]:
            """Railway-oriented credential verification."""
            if not self.credential_hash:
                return FlextResult.fail("No credential hash set")

            import bcrypt

            try:
                result = bcrypt.checkpw(
                    credential.encode("utf-8"), self.credential_hash.encode("utf-8")
                )
                return FlextResult.ok(result)
            except Exception as e:
                return FlextResult.fail(f"Credential verification failed: {e}")

        def set_credential(self, credential: str) -> FlextResult[Self]:
            """Railway-oriented credential setting."""
            import bcrypt

            try:
                salt = bcrypt.gensalt(FlextAuthConstants.HASH_ROUNDS_DEFAULT)
                self.credential_hash = bcrypt.hashpw(
                    credential.encode("utf-8"), salt
                ).decode("utf-8")
                return FlextResult.ok(self)
            except Exception as e:
                return FlextResult.fail(f"Credential hashing failed: {e}")

    # =========================================================================
    # GENERIC REMAINING MODELS - MINIMAL DECLARATIONS
    # =========================================================================

    class Role(FlextModels.Entity):
        """Generic role model with consolidated fields."""

        name: str = Field(..., description="Role name", min_length=1, max_length=50)
        description: str | None = Field(
            default=None, description="Description", max_length=500
        )
        permissions: PermissionsField = Field(
            default_factory=list, description="Permissions"
        )

    class Session(FlextModels.Entity):
        """Generic session model with composition."""

        identity_id: str = Field(..., description="Identity ID")
        session_token: TokenField = Field(
            ..., description="Session token", exclude=True
        )
        expires_at: datetime = Field(..., description="Expiration time")
        is_active: BoolField = Field(default=True, description="Active status")
        ip_address: str | None = Field(default=None, description="IP address")
        user_agent: str | None = Field(default=None, description="User agent")
        last_accessed_at: datetime = Field(
            default_factory=lambda: datetime.now(UTC), description="Last access time"
        )

    class AuthToken(FlextModels.Entity):
        """Generic auth token model with railway-oriented creation."""

        identity_id: str = Field(..., description="Identity ID")
        token: TokenField = Field(..., description="Token string", exclude=True)
        expires_at: datetime = Field(..., description="Expiration time")
        is_revoked: BoolField = Field(default=False, description="Revoked status")
        token_type: str = Field(default="bearer", description="Token type")
        session_id: str | None = Field(default=None, description="Session ID")
        refresh_token: str | None = Field(
            default=None, description="Refresh token", exclude=True
        )
        metadata: dict[str, object] | None = Field(
            default_factory=dict, description="Metadata"
        )

        @classmethod
        def create_token(
            cls,
            identity_id: str,
            expiry_minutes: int = 60,
            token_type: str = "access",
        ) -> FlextResult[Self]:
            """Railway-oriented token creation."""
            import secrets
            from datetime import timedelta

            return (
                FlextResult.ok(None)
                .map(lambda _: datetime.now(UTC) + timedelta(minutes=expiry_minutes))
                .map(lambda exp: f"token_{identity_id}_{secrets.token_urlsafe(32)}")
                .map(
                    lambda token: cls(
                        identity_id=identity_id,
                        token=token,
                        expires_at=exp,
                        token_type=token_type,
                    )
                )
                .recover(lambda e: FlextResult.fail(f"Token creation failed: {e}"))
            )


__all__ = ["FlextAuthModels"]

"""Domain events for FLEXT-AUTH.

Using flext-core patterns and modern Python 3.13 for zero duplication.
Clean architecture with domain events for business logic orchestration.
"""

from __future__ import annotations

from datetime import datetime  # noqa: TC003
from typing import TYPE_CHECKING

from flext_core import Field

if TYPE_CHECKING:
    from flext_core.domain.types import EntityId, UserId
else:
    # Runtime imports needed for model_rebuild()
    pass

if TYPE_CHECKING:
    from flext_auth.domain.value_objects import (
        UserEmail,
        Username,
        UserRole as SecurityRole,
    )
else:
    # Runtime imports needed for model_rebuild()
    from flext_auth.domain.value_objects import (
        UserEmail,  # noqa: TC001
        Username,  # noqa: TC001
        UserRole as SecurityRole,  # noqa: TC001
    )

from flext_core.domain.pydantic_base import DomainEvent


class UserCreated(DomainEvent):
    """Event raised when a new user is created."""

    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    email: UserEmail = Field(..., description="User email")
    created_by: UserId | None = Field(None, description="User who created this user")
    initial_roles: list[SecurityRole] = Field(
        default_factory=list,
        description="Initial roles",
    )


class UserLoggedIn(DomainEvent):
    """Event raised when user successfully logs in."""

    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    session_id: str = Field(..., description="Session ID")
    ip_address: str | None = Field(None, description="IP address")
    user_agent: str | None = Field(None, description="User agent")


class UserLoggedOut(DomainEvent):
    """Event raised when user logs out."""

    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    session_id: str = Field(..., description="Session ID")


class UserPasswordChanged(DomainEvent):
    """Event raised when user password is changed."""

    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    changed_by: UserId | None = Field(None, description="User who changed the password")


class UserRoleChanged(DomainEvent):
    """Event raised when user roles are modified."""

    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    role: SecurityRole = Field(..., description="Role that was changed")
    action: str = Field(..., description="Action taken: 'added' or 'removed'")
    changed_by: UserId = Field(..., description="User who made the change")
    previous_roles: list[SecurityRole] = Field(..., description="Previous roles")
    new_roles: list[SecurityRole] = Field(..., description="New roles")


class UserAccountLocked(DomainEvent):
    """Event raised when user account is locked."""

    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    locked_by: UserId = Field(..., description="User who locked the account")
    lock_reason: str = Field(..., description="Reason for locking")
    lock_duration_minutes: int = Field(..., description="Lock duration in minutes")


class SessionCreated(DomainEvent):
    """Event raised when a new session is created."""

    session_id: str = Field(..., description="Session ID")
    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    expires_at: datetime = Field(..., description="Session expiration time")
    ip_address: str | None = Field(None, description="IP address")
    user_agent: str | None = Field(None, description="User agent")


class TokenIssued(DomainEvent):
    """Event raised when a token is issued."""

    token_id: EntityId = Field(..., description="Token ID")
    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    token_type: str = Field(..., description="Token type")
    expires_at: datetime = Field(..., description="Token expiration time")
    scopes: list[str] = Field(default_factory=list, description="Token scopes")
    client_id: str | None = Field(None, description="Client ID")
    ip_address: str | None = Field(None, description="IP address")


class TokenRevoked(DomainEvent):
    """Event raised when a token is revoked."""

    token_id: EntityId = Field(..., description="Token ID")
    user_id: EntityId = Field(..., description="User ID")
    username: Username = Field(..., description="Username")
    token_type: str = Field(..., description="Token type")
    revoked_by: UserId | None = Field(None, description="User who revoked the token")
    revocation_reason: str = Field(..., description="Reason for revocation")


# NOTE: model_rebuild() calls removed to prevent import circular dependency issues
# Pydantic will resolve forward references automatically when needed

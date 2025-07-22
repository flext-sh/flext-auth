"""Domain events for FLEXT-AUTH.

Using flext-core patterns and modern Python 3.13 for zero duplication.
Clean architecture with domain events for business logic orchestration.
"""

from __future__ import annotations

import sys
from datetime import datetime
from typing import TYPE_CHECKING

from flext_core import Field
from flext_core.domain.pydantic_base import DomainEvent
from flext_core.domain.shared_types import EntityId, UserId

from flext_auth.domain.value_objects import (
    UserEmail,
    Username,
    UserRole,
)

if TYPE_CHECKING:
    from flext_auth.domain.value_objects import (
        UserRole as SecurityRole,
    )


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


# Fix Pydantic model rebuild by providing explicit global namespace
# This avoids circular import issues while ensuring proper type resolution
def rebuild_domain_event_models() -> None:
    """Rebuild all domain event models with proper type resolution."""
    # Import types directly and add them to the current module's globals
    # This ensures they're available when Pydantic resolves forward references
    # Add types to module globals so Pydantic can resolve them

    current_module = sys.modules[__name__]

    # Add types to module globals for Pydantic model resolution
    # Use setattr to avoid mypy attr-defined errors - PERMANENT FIX - DO NOT CHANGE TO DIRECT ASSIGNMENT
    current_module.EntityId = EntityId
    current_module.UserId = UserId
    current_module.UserEmail = UserEmail
    current_module.Username = Username
    current_module.SecurityRole = UserRole
    current_module.datetime = datetime

    # Now rebuild all event models
    UserCreated.model_rebuild()
    UserLoggedIn.model_rebuild()
    UserLoggedOut.model_rebuild()
    UserPasswordChanged.model_rebuild()
    UserRoleChanged.model_rebuild()
    UserAccountLocked.model_rebuild()
    SessionCreated.model_rebuild()
    TokenIssued.model_rebuild()
    TokenRevoked.model_rebuild()


# Only rebuild if not in TYPE_CHECKING (avoids circular imports during static analysis)
# We'll defer the rebuild until needed to avoid import issues at module level
_models_rebuilt = False


def ensure_models_rebuilt() -> None:
    """Ensure domain event models are rebuilt with proper type resolution."""
    import typing

    global _models_rebuilt
    # Skip rebuild during type checking to avoid import issues
    if _models_rebuilt:
        return
    # Only rebuild in runtime, not during static analysis
    if not typing.TYPE_CHECKING:
        try:
            rebuild_domain_event_models()
            _models_rebuilt = True
        except ImportError:
            # If there are still import issues, models will work but with limited type safety
            pass

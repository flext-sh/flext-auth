"""Application commands for FLEXT-AUTH.

Command pattern implementation for CQRS architecture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Any
from typing import Literal

from pydantic import BaseModel
from pydantic import ConfigDict
from pydantic import Field

if TYPE_CHECKING:
    from datetime import timedelta
    from uuid import UUID

    from flext_auth.domain.value_objects import UserStatus

# Type alias for token types based on AuthToken validation
TokenType = Literal["access", "refresh", "api", "session"]


class Command(BaseModel):
    """Base command class for CQRS pattern."""

    model_config = ConfigDict(
        frozen=True,
        arbitrary_types_allowed=True,
        validate_assignment=True,
    )


class CreateUserCommand(Command):
    """Command to create a new user."""

    username: str = Field(..., min_length=1)
    email: str | None = None
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    is_superuser: bool = False
    is_staff: bool = False
    send_verification_email: bool = True


class UpdateUserCommand(Command):
    """Command to update user information."""

    user_id: UUID
    first_name: str | None = None
    last_name: str | None = None
    display_name: str | None = None
    email: str | None = None
    status: UserStatus | None = None
    is_superuser: bool | None = None
    is_staff: bool | None = None
    updated_by: UUID | None = None


class ChangePasswordCommand(Command):
    """Command to change user password."""

    user_id: UUID
    current_password: str | None = None
    new_password: str


class ResetPasswordCommand(Command):
    """Command to reset user password."""

    user_id: UUID
    new_password: str
    reset_token: str


class AuthenticateUserCommand(Command):
    """Command to authenticate user."""

    username: str = Field(..., min_length=1)
    password: str | None = None
    user_agent: str | None = None


class LogoutUserCommand(Command):
    """Command to logout user."""

    user_id: UUID
    session_id: UUID


class CreateTokenCommand(Command):
    """Command to create a token."""

    user_id: UUID
    token_type: TokenType
    expires_in: timedelta
    scopes: list[str] | None = None
    metadata: dict[str, Any] | None = None


class RevokeTokenCommand(Command):
    """Command to revoke a token."""

    token_id: UUID
    revoked_by: UUID | None = None


class CreateSessionCommand(Command):
    """Command to create a session."""

    user_id: UUID
    expires_in: timedelta | None = None
    user_agent: str | None = None


class RefreshSessionCommand(Command):
    """Command to refresh a session."""

    session_id: UUID
    duration: timedelta


class DeactivateSessionCommand(Command):
    """Command to deactivate a session."""

    session_id: UUID


class CreateRoleCommand(Command):
    """Command to create a role."""

    name: str = Field(..., min_length=1)
    description: str | None = None
    permissions: list[str] | None = None
    is_system: bool = False
    parent_role_id: UUID | None = None


class UpdateRoleCommand(Command):
    """Command to update a role."""

    role_id: UUID
    name: str | None = None
    description: str | None = None
    permissions: list[str] | None = None
    parent_role_id: UUID | None = None


class AssignRoleCommand(Command):
    """Command to assign role to user."""

    user_id: UUID
    role_id: UUID | None = None


class RemoveRoleCommand(Command):
    """Command to remove role from user."""

    user_id: UUID
    role_id: UUID | None = None


class VerifyEmailCommand(Command):
    """Command to verify user email."""

    user_id: UUID
    verification_token: str


class SendPasswordResetCommand(Command):
    """Command to send password reset email."""

    email: str = Field(..., min_length=1)


class LockUserCommand(Command):
    """Command to lock user account."""

    user_id: UUID
    duration: timedelta | None = None
    reason: str | None = None


class UnlockUserCommand(Command):
    """Command to unlock user account."""

    user_id: UUID
    unlocked_by: UUID | None = None

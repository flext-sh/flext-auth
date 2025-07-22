"""Application commands for FLEXT-AUTH.

Command pattern implementation for CQRS architecture.
"""
from __future__ import annotations

from typing import TYPE_CHECKING, Any, Literal

from flext_core import Field
from pydantic import BaseModel, ConfigDict

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
    new_password: str = Field(..., min_length=1)


class ResetPasswordCommand(Command):
    """Command to reset user password."""

    user_id: UUID
    new_password: str = Field(..., min_length=1)
    reset_token: str = Field(..., min_length=1)


class AuthenticateUserCommand(Command):
    """Command to authenticate user."""

    username: str = Field(..., min_length=1)
    password: str | None = None
    user_agent: str | None = None
    ip_address: str | None = None


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
    verification_token: str = Field(..., min_length=1)


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


# Rebuild models to resolve forward references
def rebuild_command_models() -> None:
    """Rebuild all command models with proper type resolution."""
    # Import types directly and add them to the current module's globals
    # Add types to module globals so Pydantic can resolve them
    import sys
    from datetime import timedelta
    from uuid import UUID

    from flext_auth.domain.value_objects import UserStatus
    current_module = sys.modules[__name__]
    # Add types to module globals for Pydantic model resolution
    # Use setattr to properly expose types for Pydantic model resolution
    current_module.UUID = UUID
    current_module.timedelta = timedelta
    current_module.UserStatus = UserStatus
    # Rebuild all command models that use forward references
    CreateUserCommand.model_rebuild()
    UpdateUserCommand.model_rebuild()
    ChangePasswordCommand.model_rebuild()
    AuthenticateUserCommand.model_rebuild()
    CreateSessionCommand.model_rebuild()
    RefreshSessionCommand.model_rebuild()
    LogoutUserCommand.model_rebuild()
    DeactivateSessionCommand.model_rebuild()
    CreateTokenCommand.model_rebuild()
    RevokeTokenCommand.model_rebuild()
    CreateRoleCommand.model_rebuild()
    UpdateRoleCommand.model_rebuild()
    AssignRoleCommand.model_rebuild()
    RemoveRoleCommand.model_rebuild()
    VerifyEmailCommand.model_rebuild()
    SendPasswordResetCommand.model_rebuild()
    ResetPasswordCommand.model_rebuild()
    LockUserCommand.model_rebuild()
    UnlockUserCommand.model_rebuild()


# Only rebuild if not in TYPE_CHECKING
_models_rebuilt = False


def ensure_command_models_rebuilt() -> None:
    """Ensure command models are rebuilt with proper type resolution."""
    import typing
    global _models_rebuilt
    if _models_rebuilt:
        return
    # Only rebuild in runtime, not during static analysis
    if not typing.TYPE_CHECKING:
        try:
            rebuild_command_models()
            _models_rebuilt = True
        except ImportError:
            # If there are still import issues, models will work with limited type safety
            pass

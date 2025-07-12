"""Commands for FLEXT Auth domain.

Using flext-core patterns - no duplication.
"""

from uuid import UUID

from pydantic import EmailStr
from pydantic import Field


class CreateUserCommand:
    """Command to create a new user."""

    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password = Field(..., min_length=8)
    roles: list[str] = Field(default_factory=list)


class AuthenticateUserCommand:
    """Command to authenticate a user."""

    username: str
    password = None
    user_agent: str | None = None


class GenerateTokenCommand:
    """Command to generate a token."""

    user_id: UUID
    token_type = "access"  # access, refresh
    expires_in: int | None = None  # seconds


class ValidateTokenCommand:
    """Command to validate a token."""

    token: str
    token_type = "access"


class RefreshTokenCommand:
    """Command to refresh an access token."""

    refresh_token: str


class RevokeTokenCommand:
    """Command to revoke a token."""

    token: str
    reason = None


class ChangePasswordCommand:
    """Command to change user password."""

    user_id: UUID
    current_password = Field(..., min_length=8)


class AssignRoleCommand:
    """Command to assign role to user."""

    user_id: UUID
    role_name: str

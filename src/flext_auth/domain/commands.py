"""Commands for FLEXT Auth domain.

Using flext-core patterns - no duplication.
"""

from dataclasses import dataclass, field
from uuid import UUID

from pydantic import EmailStr


@dataclass
class CreateUserCommand:
    """Command to create a new user."""

    username: str
    email: EmailStr
    password: str
    roles: list[str] = field(default_factory=list)


@dataclass
class AuthenticateUserCommand:
    """Command to authenticate a user."""

    username: str
    password: str
    user_agent: str | None = None


@dataclass
class GenerateTokenCommand:
    """Command to generate a token."""

    user_id: UUID
    token_type: str = "access"  # access, refresh
    expires_in: int | None = None  # seconds


@dataclass
class ValidateTokenCommand:
    """Command to validate a token."""

    token: str
    token_type: str = "access"


@dataclass
class RefreshTokenCommand:
    """Command to refresh an access token."""

    refresh_token: str


@dataclass
class RevokeTokenCommand:
    """Command to revoke a token."""

    token: str
    reason: str | None = None


@dataclass
class ChangePasswordCommand:
    """Command to change user password."""

    user_id: UUID
    current_password: str
    new_password: str


@dataclass
class AssignRoleCommand:
    """Command to assign role to user."""

    user_id: UUID
    role_name: str

"""Repository interfaces for FLEXT Auth domain.

Built on flext-core foundation for clean repository pattern.
Defines abstract interfaces for data access operations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from uuid import UUID

    from flext_core import ServiceResult

    from flext_auth.domain.entities import Role, Session, User


class UserRepository(ABC):
    """Repository interface for User entities using flext-core patterns."""

    @abstractmethod
    async def find_by_username(self, username: str) -> ServiceResult[User | None]:
        """Find user by username."""
        ...

    @abstractmethod
    async def find_by_email(self, email: str) -> ServiceResult[User | None]:
        """Find user by email address."""
        ...

    @abstractmethod
    async def find_by_id(self, user_id: UUID) -> ServiceResult[User | None]:
        """Find user by ID."""
        ...

    @abstractmethod
    async def create(self, user: User) -> ServiceResult[User]:
        """Create a new user."""
        ...

    @abstractmethod
    async def update(self, user: User) -> ServiceResult[User]:
        """Update an existing user."""
        ...

    @abstractmethod
    async def delete(self, user_id: UUID) -> ServiceResult[bool]:
        """Delete a user by ID."""
        ...

    @abstractmethod
    async def username_exists(self, username: str) -> ServiceResult[bool]:
        """Check if username already exists."""
        ...

    @abstractmethod
    async def email_exists(self, email: str) -> ServiceResult[bool]:
        """Check if email already exists."""
        ...

    @abstractmethod
    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> ServiceResult[list[User]]:
        """List users with pagination."""
        ...


class RoleRepository(ABC):
    """Repository interface for Role entities using flext-core patterns."""

    @abstractmethod
    async def find_by_name(self, name: str) -> ServiceResult[Role | None]:
        """Find role by name."""
        ...

    @abstractmethod
    async def find_by_id(self, role_id: UUID) -> ServiceResult[Role | None]:
        """Find role by ID."""
        ...

    @abstractmethod
    async def create(self, role: Role) -> ServiceResult[Role]:
        """Create a new role."""
        ...

    @abstractmethod
    async def update(self, role: Role) -> ServiceResult[Role]:
        """Update an existing role."""
        ...

    @abstractmethod
    async def delete(self, role_id: UUID) -> ServiceResult[bool]:
        """Delete a role by ID."""
        ...

    @abstractmethod
    async def list_roles(self) -> ServiceResult[list[Role]]:
        """List all available roles."""
        ...

    @abstractmethod
    async def find_user_roles(self, user_id: UUID) -> ServiceResult[list[Role]]:
        """Find all roles assigned to a user."""
        ...


class SessionRepository(ABC):
    """Repository interface for Session entities using flext-core patterns."""

    @abstractmethod
    async def find_by_token(self, token: str) -> ServiceResult[Session | None]:
        """Find session by token."""
        ...

    @abstractmethod
    async def find_by_id(self, session_id: UUID) -> ServiceResult[Session | None]:
        """Find session by ID."""
        ...

    @abstractmethod
    async def create(self, session: Session) -> ServiceResult[Session]:
        """Create a new session."""
        ...

    @abstractmethod
    async def update(self, session: Session) -> ServiceResult[Session]:
        """Update an existing session."""
        ...

    @abstractmethod
    async def delete(self, session_id: UUID) -> ServiceResult[bool]:
        """Delete a session by ID."""
        ...

    @abstractmethod
    async def find_active_by_user(self, user_id: UUID) -> ServiceResult[list[Session]]:
        """Find all active sessions for a user."""
        ...

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: UUID) -> ServiceResult[int]:
        """Revoke all sessions for a user."""
        ...

    @abstractmethod
    async def cleanup_expired_sessions(self) -> ServiceResult[int]:
        """Clean up expired sessions."""
        ...

    @abstractmethod
    async def find_sessions_by_user(
        self,
        user_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> ServiceResult[list[Session]]:
        """Find sessions for a user with pagination."""
        ...

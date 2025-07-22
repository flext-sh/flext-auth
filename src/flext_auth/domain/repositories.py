"""Repository interfaces for FLEXT Auth domain.

Built on flext-core foundation for clean repository pattern.
Defines abstract interfaces for data access operations.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from uuid import UUID

    from flext_core.domain.shared_types import ServiceResult

    from flext_auth.domain.entities import Role, Session, User


class UserRepository(ABC):
    """Repository interface for User entities using flext-core patterns."""

    @abstractmethod
    async def find_by_username(self, username: str) -> ServiceResult[Any]:
        """Find user by username."""
        ...

    @abstractmethod
    async def find_by_email(self, email: str) -> ServiceResult[Any]:
        """Find user by email address."""
        ...

    @abstractmethod
    async def find_by_id(self, user_id: UUID) -> ServiceResult[Any]:
        """Find user by ID."""
        ...

    @abstractmethod
    async def create(self, user: User) -> ServiceResult[Any]:
        """Create a new user."""
        ...

    @abstractmethod
    async def update(self, user: User) -> ServiceResult[Any]:
        """Update an existing user."""
        ...

    @abstractmethod
    async def delete(self, user_id: UUID) -> ServiceResult[Any]:
        """Delete a user by ID."""
        ...

    @abstractmethod
    async def username_exists(self, username: str) -> ServiceResult[Any]:
        """Check if username already exists."""
        ...

    @abstractmethod
    async def email_exists(self, email: str) -> ServiceResult[Any]:
        """Check if email already exists."""
        ...

    @abstractmethod
    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> ServiceResult[Any]:
        """List users with pagination."""
        ...


class RoleRepository(ABC):
    """Repository interface for Role entities using flext-core patterns."""

    @abstractmethod
    async def find_by_name(self, name: str) -> ServiceResult[Any]:
        """Find role by name."""
        ...

    @abstractmethod
    async def find_by_id(self, role_id: UUID) -> ServiceResult[Any]:
        """Find role by ID."""
        ...

    @abstractmethod
    async def create(self, role: Role) -> ServiceResult[Any]:
        """Create a new role."""
        ...

    @abstractmethod
    async def update(self, role: Role) -> ServiceResult[Any]:
        """Update an existing role."""
        ...

    @abstractmethod
    async def delete(self, role_id: UUID) -> ServiceResult[Any]:
        """Delete a role by ID."""
        ...

    @abstractmethod
    async def list_roles(self) -> ServiceResult[Any]:
        """List all available roles."""
        ...

    @abstractmethod
    async def find_user_roles(self, user_id: UUID) -> ServiceResult[Any]:
        """Find all roles assigned to a user."""
        ...


class SessionRepository(ABC):
    """Repository interface for Session entities using flext-core patterns."""

    @abstractmethod
    async def find_by_token(self, token: str) -> ServiceResult[Any]:
        """Find session by token."""
        ...

    @abstractmethod
    async def find_by_id(self, session_id: UUID) -> ServiceResult[Any]:
        """Find session by ID."""
        ...

    @abstractmethod
    async def create(self, session: Session) -> ServiceResult[Any]:
        """Create a new session."""
        ...

    @abstractmethod
    async def update(self, session: Session) -> ServiceResult[Any]:
        """Update an existing session."""
        ...

    @abstractmethod
    async def delete(self, session_id: UUID) -> ServiceResult[Any]:
        """Delete a session by ID."""
        ...

    @abstractmethod
    async def find_active_by_user(self, user_id: UUID) -> ServiceResult[Any]:
        """Find all active sessions for a user."""
        ...

    @abstractmethod
    async def revoke_all_user_sessions(self, user_id: UUID) -> ServiceResult[Any]:
        """Revoke all sessions for a user."""
        ...

    @abstractmethod
    async def cleanup_expired_sessions(self) -> ServiceResult[Any]:
        """Clean up expired sessions."""
        ...

    @abstractmethod
    async def find_sessions_by_user(
        self,
        user_id: UUID,
        limit: int = 50,
        offset: int = 0,
    ) -> ServiceResult[Any]:
        """Find sessions for a user with pagination."""
        ...

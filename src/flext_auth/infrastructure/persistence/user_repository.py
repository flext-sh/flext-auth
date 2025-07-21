"""Real PostgreSQL user repository implementation - ZERO TOLERANCE for mocks."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core import ServiceResult
from flext_observability.logging import get_logger
from sqlalchemy import delete, func, select

from flext_auth.domain.entities import User
from flext_auth.domain.repositories import UserRepository
from flext_auth.infrastructure.persistence.models import UserModel

if TYPE_CHECKING:
    from uuid import UUID

    from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker

logger = get_logger(__name__)


class PostgreSQLUserRepository(UserRepository):
    """Real PostgreSQL implementation of UserRepository.

    Uses SQLAlchemy 2.0 async patterns with proper error handling.
    ZERO TOLERANCE - No mocks, no fake implementations.
    """

    def __init__(self, session_maker: async_sessionmaker[AsyncSession]) -> None:
        """Initialize repository with async session maker.

        Args:
            session_maker: SQLAlchemy async session maker configured for PostgreSQL

        """
        self._session_maker = session_maker

    def _model_to_entity(self, model: UserModel) -> User:
        """Convert SQLAlchemy model to domain entity."""
        return User(
            id=model.id,
            username=model.username,
            email=model.email,
            password_hash=model.password_hash,
            role=model.role,
            status=model.status,
            email_verified=model.email_verified,
            email_verified_at=model.email_verified_at,
            last_login_at=model.last_login_at,
            last_login_ip=model.last_login_ip,
            login_attempts=model.login_attempts,
            locked_until=model.locked_until,
            created_at=model.created_at,
            updated_at=model.updated_at,
        )

    def _entity_to_model(self, entity: User) -> UserModel:
        """Convert domain entity to SQLAlchemy model."""
        return UserModel(
            id=entity.id,
            username=entity.username,
            email=entity.email,
            password_hash=entity.password_hash,
            role=entity.role,
            status=entity.status,
            email_verified=entity.email_verified,
            email_verified_at=entity.email_verified_at,
            last_login_at=entity.last_login_at,
            last_login_ip=entity.last_login_ip,
            login_attempts=entity.login_attempts,
            locked_until=entity.locked_until,
            created_at=entity.created_at,
            updated_at=entity.updated_at,
        )

    async def find_by_id(self, user_id: UUID) -> ServiceResult[User | None]:
        """Find user by ID.

        Args:
            user_id: The user ID to search for

        Returns:
            ServiceResult containing the User if found, None if not found, or error

        """
        try:
            async with self._session_maker() as session:
                result = await session.execute(
                    select(UserModel).where(UserModel.id == user_id),
                )
                user_model = result.scalar_one_or_none()
                if user_model is None:
                    return ServiceResult.ok(None)
                user = self._model_to_entity(user_model)
                return ServiceResult.ok(user)
        except Exception as e:
            logger.exception("Failed to get user by ID")
            return ServiceResult.fail(f"Failed to get user: {e}")

    async def find_by_username(self, username: str) -> ServiceResult[User | None]:
        """Find user by username.

        Args:
            username: The username to search for

        Returns:
            ServiceResult containing the User if found, None if not found, or error

        """
        try:
            async with self._session_maker() as session:
                result = await session.execute(
                    select(UserModel).where(UserModel.username == username),
                )
                user_model = result.scalar_one_or_none()
                if user_model is None:
                    return ServiceResult.ok(None)
                user = self._model_to_entity(user_model)
                return ServiceResult.ok(user)
        except Exception as e:
            logger.exception("Failed to find user by username")
            return ServiceResult.fail(f"Database error finding user by username: {e}")

    async def find_by_email(self, email: str) -> ServiceResult[User | None]:
        """Find user by email address.

        Args:
            email: The email address to search for

        Returns:
            ServiceResult containing the User if found, None if not found, or error

        """
        try:
            async with self._session_maker() as session:
                result = await session.execute(
                    select(UserModel).where(UserModel.email == email),
                )
                user_model = result.scalar_one_or_none()
                if user_model is None:
                    return ServiceResult.ok(None)
                user = self._model_to_entity(user_model)
                return ServiceResult.ok(user)
        except Exception as e:
            logger.exception("Failed to find user by email")
            return ServiceResult.fail(f"Database error finding user by email: {e}")

    async def create(self, user: User) -> ServiceResult[User]:
        """Create a new user.

        Args:
            user: The User entity to create

        Returns:
            ServiceResult containing the created User or error

        """
        try:
            async with self._session_maker() as session:
                user_model = self._entity_to_model(user)
                session.add(user_model)
                await session.commit()
                await session.refresh(user_model)
                created_user = self._model_to_entity(user_model)
                return ServiceResult.ok(created_user)
        except Exception as e:
            logger.exception("Failed to create user")
            return ServiceResult.fail(f"Database error creating user: {e}")

    async def update(self, user: User) -> ServiceResult[User]:
        """Update an existing user.

        Args:
            user: The User entity to update

        Returns:
            ServiceResult containing the updated User or error

        """
        try:
            async with self._session_maker() as session:
                user_model = self._entity_to_model(user)
                merged_model = await session.merge(user_model)
                await session.commit()
                await session.refresh(merged_model)
                updated_user = self._model_to_entity(merged_model)
                return ServiceResult.ok(updated_user)
        except Exception as e:
            logger.exception("Failed to update user")
            return ServiceResult.fail(f"Database error updating user: {e}")

    async def delete(self, user_id: UUID) -> ServiceResult[bool]:
        """Delete a user by ID.

        Args:
            user_id: The ID of the user to delete

        Returns:
            ServiceResult containing True if deleted, False if not found, or error

        """
        try:
            async with self._session_maker() as session:
                result = await session.execute(
                    delete(UserModel).where(UserModel.id == user_id),
                )
                deleted = result.rowcount > 0
                await session.commit()
                return ServiceResult.ok(deleted)
        except Exception as e:
            logger.exception("Failed to delete user")
            return ServiceResult.fail(f"Database error deleting user: {e}")

    async def username_exists(self, username: str) -> ServiceResult[bool]:
        """Check if username already exists.

        Args:
            username: The username to check

        Returns:
            ServiceResult containing True if exists, False if not, or error

        """
        try:
            async with self._session_maker() as session:
                result = await session.execute(
                    select(func.count(UserModel.id)).where(
                        UserModel.username == username,
                    ),
                )
                count = result.scalar()
                exists = count is not None and count > 0
                return ServiceResult.ok(exists)
        except Exception as e:
            logger.exception("Failed to check username exists")
            return ServiceResult.fail(f"Database error checking username exists: {e}")

    async def email_exists(self, email: str) -> ServiceResult[bool]:
        """Check if email already exists.

        Args:
            email: The email to check

        Returns:
            ServiceResult containing True if exists, False if not, or error

        """
        try:
            async with self._session_maker() as session:
                result = await session.execute(
                    select(func.count(UserModel.id)).where(UserModel.email == email),
                )
                count = result.scalar()
                exists = count is not None and count > 0
                return ServiceResult.ok(exists)
        except Exception as e:
            logger.exception("Failed to check email exists")
            return ServiceResult.fail(f"Database error checking email exists: {e}")

    async def list_users(
        self,
        limit: int = 100,
        offset: int = 0,
    ) -> ServiceResult[list[User]]:
        """List users with pagination.

        Args:
            limit: Maximum number of users to return
            offset: Number of users to skip

        Returns:
            ServiceResult containing list of Users or error

        """
        try:
            async with self._session_maker() as session:
                result = await session.execute(
                    select(UserModel)
                    .order_by(UserModel.created_at.desc())
                    .limit(limit)
                    .offset(offset),
                )
                user_models = list(result.scalars().all())
                users = [self._model_to_entity(model) for model in user_models]
                return ServiceResult.ok(users)
        except Exception as e:
            logger.exception("Failed to list users")
            return ServiceResult.fail(f"Database error listing users: {e}")

    async def get_by_id(self, user_id: UUID) -> ServiceResult[User]:
        """Get user by ID (required variant that raises if not found).

        Args:
            user_id: The user ID to get

        Returns:
            ServiceResult containing the User or failure if not found

        """
        result = await self.find_by_id(user_id)
        if not result.is_success:
            return ServiceResult.fail(result.error or "Database error")

        if result.data is None:
            return ServiceResult.fail("User not found")

        return ServiceResult.ok(result.data)

    async def get_by_username(self, username: str) -> ServiceResult[User]:
        """Get user by username (required variant that raises if not found).

        Args:
            username: The username to get

        Returns:
            ServiceResult containing the User or failure if not found

        """
        result = await self.find_by_username(username)
        if not result.is_success:
            return ServiceResult.fail(result.error or "Database error")

        if result.data is None:
            return ServiceResult.fail("User not found")

        return ServiceResult.ok(result.data)

    async def get_by_email(self, email: str) -> ServiceResult[User]:
        """Get user by email (required variant that raises if not found).

        Args:
            email: The email to get

        Returns:
            ServiceResult containing the User or failure if not found

        """
        result = await self.find_by_email(email)
        if not result.is_success:
            return ServiceResult.fail(result.error or "Database error")

        if result.data is None:
            return ServiceResult.fail("User not found")

        return ServiceResult.ok(result.data)

    async def save(self, user: User) -> ServiceResult[User]:
        """Save user (create or update based on existence).

        Args:
            user: The User entity to save

        Returns:
            ServiceResult containing the saved User or error

        """
        # Check if user exists
        if hasattr(user, "id") and user.id:
            existing_result = await self.find_by_id(user.id)
            if existing_result.is_success and existing_result.data is not None:
                # User exists, update it
                return await self.update(user)

        # User doesn't exist, create it
        return await self.create(user)

"""FLEXT AUTH Application Services - Business logic orchestration.

Using flext-core patterns and modern Python 3.13 for zero duplication.
Clean architecture with dependency injection and type safety.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import uuid4

from flext_core.domain.shared_types import ServiceResult

from flext_auth.domain.entities import Session, User
from flext_auth.domain.events import (
    SessionCreated,
    TokenIssued,
    UserCreated,
    UserLoggedIn,
    UserLoggedOut,
    ensure_models_rebuilt,
)
from flext_auth.domain.value_objects import (
    AuthToken,
    UserEmail,
    Username,
    UserRole as SecurityRole,
)

if TYPE_CHECKING:
    from flext_core.domain.shared_types import UserId

# Ensure domain event models are rebuilt when ap    plication services are used
ensure_models_rebuilt()


class AuthService:
    """Authentication service using flext-core patterns."""

    def __init__(
        self,
        user_repository: Any,
        token_repository: Any,
        session_repository: Any,
        password_hasher: Any,
        token_generator: Any,
        event_bus: Any,
    ) -> None:
        self.user_repository = user_repository
        self.token_repository = token_repository
        self.session_repository = session_repository
        self.password_hasher = password_hasher
        self.token_generator = token_generator
        self.event_bus = event_bus

    async def authenticate_user(
        self,
        username: Username,
        password: str,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> ServiceResult[Any]:
        """Authenticate a user with username and password."""
        try:
            # Find user by username
            user_result = await self.user_repository.get_by_username(username)
            if not user_result.success:
                return ServiceResult.fail("Invalid username or password",
                )

            user = user_result.data

            # Check if user can login
            if not user.is_active():
                return ServiceResult.fail("Account is not active")

            if user.is_locked():
                return ServiceResult.fail("Account is locked")

            # Verify password
            password_valid = await self.password_hasher.verify_password(
                password,
                user.password_hash,
            )
            if not password_valid:
                user.record_login_attempt(
                    success=False,
                    ip_address=ip_address or "unknown",
                )
                await self.user_repository.update(user)
                return ServiceResult.fail("Invalid username or password",
                )

            # Success - record login
            user.record_login_attempt(success=True, ip_address=ip_address or "unknown")
            await self.user_repository.update(user)

            # Publish event
            event = UserLoggedIn(
                user_id=user.id,
                username=Username(value=user.username),
                session_id="",
                ip_address=ip_address or "",
                user_agent=user_agent or "",
            )
            await self.event_bus.publish(event)

            return ServiceResult.ok(user)

        except Exception as e:
            return ServiceResult.fail(f"Authentication failed: {e!s}")

    async def logout_user(
        self,
        user_id: UserId,
        session_id: str,
    ) -> ServiceResult[Any]:
        """Log out a user and invalidate their session."""
        try:
            # Get user
            user_result = await self.user_repository.find_by_id(user_id)
            if not user_result.success:
                return ServiceResult.fail("User not found")

            user = user_result.data

            # Invalidate session
            session_result = await self.session_repository.find_by_id(session_id)
            if session_result.success:
                session = session_result.data
                session.revoke()
                await self.session_repository.save(session)

            # Publish event
            event = UserLoggedOut(
                user_id=user.id,
                username=Username(value=user.username),
                session_id=str(session_id),
            )
            await self.event_bus.publish(event)

            return ServiceResult.ok(None)

        except Exception as e:
            return ServiceResult.fail(f"Logout failed: {e!s}")

    async def validate_token(self, token_value: str) -> ServiceResult[Any]:
        """Validate an authentication token."""
        try:
            # Get token
            token_result = await self.token_repository.get_by_value(token_value)
            if not token_result.success:
                return ServiceResult.fail("Invalid token")

            token = token_result.data
            if token is None:
                return ServiceResult.fail("Token not found")

            # Check if token is valid
            if not token.is_valid:
                return ServiceResult.fail("Token is invalid or expired")

            # Record usage
            token.record_use()
            await self.token_repository.update(token)

            return ServiceResult.ok(token)

        except Exception as e:
            return ServiceResult.fail(f"Token validation failed: {e!s}")

    async def create_user(
        self,
        username: Username,
        email: str,
        password: str,
        roles: list[str] | None = None,
    ) -> ServiceResult[Any]:
        """Create a new user account."""
        try:
            # Check if username already exists
            existing_username_result = await self.user_repository.get_by_username(
                username,
            )
            if existing_username_result.success:
                return ServiceResult.fail("Username already exists")

            # Check if email already exists
            existing_email_result = await self.user_repository.get_by_email(email)
            if existing_email_result.success:
                return ServiceResult.fail("Email already exists")

            # Hash password
            password_hash = await self.password_hasher.hash_password(password)

            # Create user entity
            user = User(
                id=uuid4(),
                username=username.value,
                email=email,
                password_hash=password_hash,
                email_verified_at=None,
                last_login_at=None,
                last_login_ip=None,
                locked_until=None,
            )

            # Save to repository
            save_result = await self.user_repository.save(user)
            if not save_result.success:
                return ServiceResult.fail("Failed to create user")

            # Emit domain event
            event = UserCreated(
                user_id=user.id,
                username=username,
                email=UserEmail(value=user.email),
            )
            await self.event_bus.publish(event)

            return ServiceResult.ok(user)

        except Exception as e:
            return ServiceResult.fail(f"User creation failed: {e!s}")

    async def change_password(
        self,
        user_id: UserId,
        current_password: str,
        new_password: str,
    ) -> ServiceResult[Any]:
        """Change a user's password."""
        try:
            # Get user
            user_result = await self.user_repository.find_by_id(user_id)
            if not user_result.success:
                return ServiceResult.fail("User not found")

            user = user_result.data

            # Verify current password
            password_valid = await self.password_hasher.verify_password(
                current_password,
                user.password_hash,
            )
            if not password_valid:
                return ServiceResult.fail("Current password is incorrect",
                )

            # Hash new password
            new_password_hash = await self.password_hasher.hash_password(new_password)

            # Update user password
            user.password_hash = new_password_hash
            save_result = await self.user_repository.save(user)
            if not save_result.success:
                return ServiceResult.fail("Failed to update password")

            return ServiceResult.ok(True)

        except Exception as e:
            return ServiceResult.fail(f"Password change failed: {e!s}")


class UserService:
    """User management service using flext-core patterns."""

    def __init__(
        self,
        user_repository: Any,
        role_repository: Any,
        password_hasher: Any,
        event_bus: Any,
    ) -> None:
        self.user_repository = user_repository
        self.role_repository = role_repository
        self.password_hasher = password_hasher
        self.event_bus = event_bus

    async def create_user(
        self,
        username: Username,
        email: UserEmail,
        password: str,
        roles: list[SecurityRole] | None = None,
        created_by: UserId | None = None,
    ) -> ServiceResult[Any]:
        """Create a new user account."""
        try:
            # Check if username exists
            existing_user = await self.user_repository.get_by_username(username)
            if existing_user.is_success:
                return ServiceResult.fail("Username already exists")

            # Check if email exists
            existing_email = await self.user_repository.get_by_email(email)
            if existing_email.is_success:
                return ServiceResult.fail("Email already exists")

            # Hash password
            password_hash = self.password_hasher.hash_password(password)

            # Create user
            user = User(
                username=str(username),
                email=str(email),
                password_hash=password_hash,
                role=roles[0] if roles else "user",
                email_verified_at=None,
                last_login_at=None,
                last_login_ip=None,
                locked_until=None,
            )

            # Save user
            save_result = await self.user_repository.save(user)
            if not save_result.success:
                return ServiceResult.fail("Failed to save user")

            # Publish event
            event = UserCreated(
                user_id=user.id,
                username=Username(value=user.username),
                email=UserEmail(value=user.email),
                created_by=created_by,
                initial_roles=roles or [],
            )
            await self.event_bus.publish(event)

            return ServiceResult.ok(user)

        except Exception as e:
            return ServiceResult.fail(f"User creation failed: {e!s}")


class TokenService:
    """Token management service using flext-core patterns."""

    def __init__(
        self,
        token_repository: Any,
        token_generator: Any,
        event_bus: Any,
        user_repository: Any,
    ) -> None:
        self.token_repository = token_repository
        self.token_generator = token_generator
        self.event_bus = event_bus
        self.user_repository = user_repository

    async def create_token(
        self,
        user_id: UserId,
        username: Username,
        token_type: str,
        expires_in: timedelta,
        scopes: list[str] | None = None,
        client_id: str | None = None,
        ip_address: str | None = None,
    ) -> ServiceResult[Any]:
        """Create a new authentication token for a user."""
        try:
            # Generate token
            token_value = self.token_generator.generate_token()

            # Create token value object
            token = AuthToken(
                value=token_value,
                token_type=token_type,
            )

            # Save token
            save_result = await self.token_repository.save(token)
            if not save_result.success:
                return ServiceResult.fail("Failed to save token")

            # Publish event
            event = TokenIssued(
                token_id=uuid4(),
                user_id=user_id,
                username=username,
                token_type=token_type,
                expires_at=datetime.now(UTC) + expires_in,
                scopes=scopes or [],
                client_id=client_id,
                ip_address=ip_address,
            )
            await self.event_bus.publish(event)

            return ServiceResult.ok(token)

        except Exception as e:
            return ServiceResult.fail(f"Token creation failed: {e!s}")


class SessionService:
    """Session management service using flext-core patterns."""

    def __init__(
        self,
        session_repository: Any,
        session_generator: Any,
        event_bus: Any,
    ) -> None:
        self.session_repository = session_repository
        self.session_generator = session_generator
        self.event_bus = event_bus

    async def create_session(
        self,
        user_id: UserId,
        username: Username,
        duration: timedelta,
        ip_address: str | None = None,
        user_agent: str | None = None,
    ) -> ServiceResult[Any]:
        """Create a new user session."""
        try:
            # Generate session ID
            session_id = self.session_generator.generate_session_id()

            # Create session
            session = Session(
                user_id=user_id,
                token=session_id,
                refresh_token=None,
                expires_at=datetime.now(UTC) + duration,
                ip_address=ip_address or "unknown",
                user_agent=user_agent or "unknown",
            )

            # Save session
            save_result = await self.session_repository.save(session)
            if not save_result.success:
                return ServiceResult.fail("Failed to save session")

            # Publish event
            event = SessionCreated(
                session_id=session_id,
                user_id=user_id,
                username=username,
                expires_at=session.expires_at,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await self.event_bus.publish(event)
            return ServiceResult.ok(session)

        except Exception as e:
            return ServiceResult.fail(f"Session creation failed: {e!s}")


# Type aliases for dependency injection
UserRepository = Any
TokenRepository = Any
SessionRepository = Any
RoleRepository = Any
PasswordHasher = Any
TokenGenerator = Any
SessionGenerator = Any
EventBus = Any

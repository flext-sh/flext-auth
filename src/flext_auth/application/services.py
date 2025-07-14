"""FLEXT AUTH Application Services - Business logic orchestration.

Using flext-core patterns and modern Python 3.13 for zero duplication.
Clean architecture with dependency injection and type safety.
"""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from typing import TYPE_CHECKING
from typing import Any

from flext_auth.domain.entities import Session
from flext_auth.domain.entities import User
from flext_auth.domain.events import SessionCreated
from flext_auth.domain.events import TokenIssued
from flext_auth.domain.events import TokenRevoked
from flext_auth.domain.events import UserAccountLocked
from flext_auth.domain.events import UserCreated
from flext_auth.domain.events import UserLoggedIn
from flext_auth.domain.events import UserLoggedOut
from flext_auth.domain.events import UserPasswordChanged
from flext_auth.domain.events import UserRoleChanged
from flext_auth.domain.value_objects import AuthToken
from flext_auth.domain.value_objects import Username
from flext_core.config import injectable
from flext_core.domain.types import EntityId
from flext_core.domain.types import ServiceResult
from flext_core.domain.types import UserId


# Runtime imports - used in actual code execution
from flext_auth.domain.value_objects import UserEmail
from flext_auth.domain.value_objects import UserRole as SecurityRole


class AuthService:
    """Authentication service using flext-core patterns."""

    def __init__(
        self,
        user_repository: UserRepository,
        token_repository: TokenRepository,
        session_repository: SessionRepository,
        password_hasher: PasswordHasher,
        token_generator: TokenGenerator,
        event_bus: EventBus,
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
    ) -> ServiceResult[User]:
        """Authenticate a user with username and password.

        Args:
            username: The username to authenticate.
            password: The user's password in plaintext.
            ip_address: Optional IP address for audit logging.
            user_agent: Optional user agent string for audit logging.

        Returns:
            ServiceResult containing the authenticated User if successful,
            or failure with error message if authentication fails.

        Raises:
            AuthenticationError: If user account is locked or disabled.

        """
        try:
            # Find user by username
            user_result = await self.user_repository.get_by_username(username)
            if not user_result.is_success:
                return ServiceResult.failure("Invalid username or password")

            user = user_result.value

            # Check if user can login:
            if not user.is_active:
                return ServiceResult.failure("Account is not active")

            if user.is_locked:
                return ServiceResult.failure("Account is locked")

            # Verify password
            if not user.password_hash.verify(password):
                user.record_failed_login()
                await self.user_repository.update(user)
                return ServiceResult.failure("Invalid username or password")

            # Success - record login
            user.record_successful_login()
            await self.user_repository.update(user)

            # Publish event
            event = UserLoggedIn(
                user_id=user.id,
                username=user.username,
                session_id="",  # Will be set by session creation
                ip_address=ip_address,
                user_agent=user_agent,
            )
            await self.event_bus.publish(event)

            return ServiceResult.success(user)

        except Exception as e:
            return ServiceResult.failure(f"Authentication failed: {e!s}")

    async def logout_user(
        self,
        user_id: UserId,
        session_id: str,
    ) -> ServiceResult[None]:
        """Log out a user and invalidate their session.

        Args:
            user_id: The ID of the user to log out.
            session_id: The session ID to invalidate.

        Returns:
            ServiceResult with None if successful, or failure with error message.

        """
        try:
            # Get user
            user_result = await self.user_repository.get_by_id(user_id)
            if not user_result.is_success:
                return ServiceResult.failure("User not found")

            user = user_result.value

            # Invalidate session
            session_result = await self.session_repository.get_by_id(session_id)
            if session_result.is_success:
                session = session_result.value
                session.deactivate()
                await self.session_repository.update(session)

            # Publish event
            event = UserLoggedOut(
                user_id=user.id,
                username=user.username,
                session_id=session_id,
            )
            await self.event_bus.publish(event)

            return ServiceResult.success(None)

        except Exception as e:
            return ServiceResult.failure(f"Logout failed: {e!s}")

    async def change_password(
        self,
        user_id: UserId,
        old_password: str,
        new_password: str,
        changed_by: UserId | None = None,
    ) -> ServiceResult[None]:
        """Change a user's password with verification.

        Args:
            user_id: The ID of the user whose password to change.
            old_password: The current password for verification.
            new_password: The new password to set.
            changed_by: Optional ID of user making the change (for REDACTED_LDAP_BIND_PASSWORD changes).

        Returns:
            ServiceResult with None if successful, or failure with error message.

        """
        try:
            # Get user
            user_result = await self.user_repository.get_by_id(user_id)
            if not user_result.is_success:
                return ServiceResult.failure("User not found")

            user = user_result.value

            # Verify old password (unless REDACTED_LDAP_BIND_PASSWORD changing)
            if (
                changed_by is None or changed_by == user_id
            ) and not user.password_hash.verify(old_password):
                return ServiceResult.failure("Invalid current password")

            # Hash new password
            new_hash = self.password_hasher.hash_password(new_password)
            user.change_password(new_hash)

            # Update user
            await self.user_repository.update(user)

            # Publish event
            event = UserPasswordChanged(
                user_id=user.id,
                username=user.username,
                changed_by=changed_by,
            )
            await self.event_bus.publish(event)

            return ServiceResult.success(None)

        except Exception as e:
            return ServiceResult.failure(f"Password change failed: {e!s}")


class UserService:
    """User management service using flext-core patterns."""

    def __init__(
        self,
        user_repository: UserRepository,
        role_repository: RoleRepository,
        password_hasher: PasswordHasher,
        event_bus: EventBus,
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
    ) -> ServiceResult[User]:
        """Create a new user account.

        Args:
            username: The username for the new user.
            email: The email address for the new user.
            password: The password for the new user.
            roles: Optional list of roles to assign to the user.
            created_by: Optional ID of user creating this account.

        Returns:
            ServiceResult containing the created User if successful,
            or failure with error message.

        """
        try:
            # Check if username exists:
            existing_user = await self.user_repository.get_by_username(username)
            if existing_user.is_success:
                return ServiceResult.failure("Username already exists")

            # Check if email exists:
            existing_email = await self.user_repository.get_by_email(email)
            if existing_email.is_success:
                return ServiceResult.failure("Email already exists")

            # Hash password
            password_hash = self.password_hasher.hash_password(password)

            # Create user
            user = User(
                username=str(username),
                email=str(email),
                password_hash=password_hash,
                role=roles[0] if roles else "user",  # Use first role or default
            )

            # Save user
            save_result = await self.user_repository.save(user)
            if not save_result.is_success:
                return ServiceResult.failure("Failed to save user")

            # Publish event
            event = UserCreated(
                user_id=user.id,
                username=Username(user.username),
                email=UserEmail(user.email),
                created_by=created_by,
                initial_roles=roles or [],
            )
            await self.event_bus.publish(event)

            return ServiceResult.success(user)

        except Exception as e:
            return ServiceResult.failure(f"User creation failed: {e!s}")

    async def update_user_roles(
        self,
        user_id: UserId,
        roles: list[SecurityRole],
        updated_by: UserId,
    ) -> ServiceResult[User]:
        """Update a user's role assignments.

        Args:
            user_id: The ID of the user to update.
            roles: The new list of roles to assign.
            updated_by: The ID of the user making this change.

        Returns:
            ServiceResult containing the updated User if successful,
            or failure with error message.

        """
        try:
            # Get user
            user_result = await self.user_repository.get_by_id(user_id)
            if not user_result.is_success:
                return ServiceResult.failure("User not found")

            user = user_result.value
            previous_roles = user.roles.copy()

            # Update roles
            user.roles.clear()
            for role in roles:
                user.add_role(role)

            # Save user
            await self.user_repository.update(user)

            # Publish events for role changes
            for role in roles:
                if role not in previous_roles:
                    event = UserRoleChanged(
                        user_id=user.id,
                        username=user.username,
                        role=role,
                        action="added",
                        changed_by=updated_by,
                        previous_roles=previous_roles,
                        new_roles=roles,
                    )
                    await self.event_bus.publish(event)

            for role in previous_roles:
                if role not in roles:
                    event = UserRoleChanged(
                        user_id=user.id,
                        username=user.username,
                        role=role,
                        action="removed",
                        changed_by=updated_by,
                        previous_roles=previous_roles,
                        new_roles=roles,
                    )
                    await self.event_bus.publish(event)

            return ServiceResult.success(user)

        except Exception as e:
            return ServiceResult.failure(f"Role update failed: {e!s}")

    async def lock_user_account(
        self,
        user_id: UserId,
        duration: timedelta,
        locked_by: UserId,
        reason: str = "manual_lock",
    ) -> ServiceResult[None]:
        """Lock a user account for a specified duration.

        Args:
            user_id: The ID of the user to lock.
            duration: How long to lock the account.
            locked_by: The ID of the user performing the lock.
            reason: The reason for locking (default: "manual_lock").

        Returns:
            ServiceResult with None if successful, or failure with error message.

        """
        try:
            # Get user
            user_result = await self.user_repository.get_by_id(user_id)
            if not user_result.is_success:
                return ServiceResult.failure("User not found")

            user = user_result.value
            user.lock_account(duration)

            # Update user
            await self.user_repository.update(user)

            # Publish event
            event = UserAccountLocked(
                user_id=user.id,
                username=user.username,
                locked_by=locked_by,
                lock_reason=reason,
                lock_duration_minutes=int(duration.total_seconds() / 60),
            )
            await self.event_bus.publish(event)

            return ServiceResult.success(None)

        except Exception as e:
            return ServiceResult.failure(f"Account lock failed: {e!s}")


class TokenService:
    """Token management service using flext-core patterns."""

    def __init__(
        self,
        token_repository: TokenRepository,
        token_generator: TokenGenerator,
        event_bus: EventBus,
    ) -> None:
        self.token_repository = token_repository
        self.token_generator = token_generator
        self.event_bus = event_bus

    async def create_token(
        self,
        user_id: UserId,
        username: Username,
        token_type: str,
        expires_in: timedelta,
        scopes: list[str] | None = None,
        client_id: str | None = None,
        ip_address: str | None = None,
    ) -> ServiceResult[AuthToken]:
        """Create a new authentication token for a user.

        Args:
            user_id: The ID of the user to create a token for.
            username: The username of the user.
            token_type: The type of token to create (e.g., 'access', 'refresh').
            expires_in: How long the token should be valid.
            scopes: Optional list of permission scopes for the token.
            client_id: Optional client identifier for the token.
            ip_address: Optional IP address for audit logging.

        Returns:
            ServiceResult containing the created AuthToken if successful,
            or failure with error message.

        """
        try:
            # Generate token
            token_value = self.token_generator.generate_token()

            # Create token value object
            token = AuthToken(
                value=token_value,
                token_type=token_type,
                user_id=user_id,
                expires_at=datetime.now(UTC) + expires_in,
                scopes=scopes or [],
            )

            # Save token
            save_result = await self.token_repository.save(token)
            if not save_result.is_success:
                return ServiceResult.failure("Failed to save token")

            # Publish event
            event = TokenIssued(
                token_id=token.id,
                user_id=user_id,
                username=username,
                token_type=token_type,
                expires_at=token.expires_at,
                scopes=scopes or [],
                client_id=client_id,
                ip_address=ip_address,
            )
            await self.event_bus.publish(event)

            return ServiceResult.success(token)

        except Exception as e:
            return ServiceResult.failure(f"Token creation failed: {e!s}")

    async def validate_token(self, token_value: str) -> ServiceResult[AuthToken]:
        """Validate an authentication token.

        Args:
            token_value: The token string to validate.

        Returns:
            ServiceResult containing the valid AuthToken if successful,
            or failure with error message if invalid.

        """
        try:
            # Get token
            token_result = await self.token_repository.get_by_value(token_value)
            if not token_result.is_success:
                return ServiceResult.failure("Invalid token")

            token = token_result.value

            # Check if token is valid:
            if not token.is_valid:
                return ServiceResult.failure("Token is invalid or expired")

            # Record usage
            token.record_use()
            await self.token_repository.update(token)

            return ServiceResult.success(token)

        except Exception as e:
            return ServiceResult.failure(f"Token validation failed: {e!s}")

    async def revoke_token(
        self,
        token_id: EntityId,
        revoked_by: UserId | None = None,
        reason: str = "manual_revocation",
    ) -> ServiceResult[None]:
        """Revoke an authentication token.

        Args:
            token_id: The ID of the token to revoke.
            revoked_by: Optional ID of user revoking the token.
            reason: The reason for revocation (default: "manual_revocation").

        Returns:
            ServiceResult with None if successful, or failure with error message.

        """
        try:
            # Get token
            token_result = await self.token_repository.get_by_id(token_id)
            if not token_result.is_success:
                return ServiceResult.failure("Token not found")

            token = token_result.value
            token.revoke(revoked_by)

            # Update token
            await self.token_repository.update(token)

            # Get user for event
            user_result = await self.user_repository.get_by_id(token.user_id)
            username = (
                user_result.value.username
                if user_result.is_success
                else Username("unknown")
            )

            # Publish event
            event = TokenRevoked(
                token_id=token.id,
                user_id=token.user_id,
                username=username,
                token_type=token.token_type,
                revoked_by=revoked_by,
                revocation_reason=reason,
            )
            await self.event_bus.publish(event)

            return ServiceResult.success(None)

        except Exception as e:
            return ServiceResult.failure(f"Token revocation failed: {e!s}")


class SessionService:
    """Session management service using flext-core patterns."""

    def __init__(
        self,
        session_repository: SessionRepository,
        session_generator: SessionGenerator,
        event_bus: EventBus,
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
    ) -> ServiceResult[Session]:
        """Create a new user session.

        Args:
            user_id: The ID of the user to create a session for.
            username: The username of the user.
            duration: How long the session should be valid.
            ip_address: Optional IP address for the session.
            user_agent: Optional user agent string for the session.

        Returns:
            ServiceResult containing the created Session if successful,
            or failure with error message.

        """
        try:
            # Generate session ID
            session_id = self.session_generator.generate_session_id()

            # Create session
            session = Session(
                user_id=user_id,
                session_token=session_id,
                expires_at=datetime.now(UTC) + duration,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            # Save session
            save_result = await self.session_repository.save(session)
            if not save_result.is_success:
                return ServiceResult.failure("Failed to save session")

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

            return ServiceResult.success(session)

        except Exception as e:
            return ServiceResult.failure(f"Session creation failed: {e!s}")

    async def validate_session(self, session_id: str) -> ServiceResult[Session]:
        """Validate a user session.

        Args:
            session_id: The session ID to validate.

        Returns:
            ServiceResult containing the valid Session if successful,
            or failure with error message if invalid.

        """
        try:
            # Get session
            session_result = await self.session_repository.get_by_token(session_id)
            if not session_result.is_success:
                return ServiceResult.failure("Invalid session")

            session = session_result.value

            # Check if session is valid:
            if not session.is_valid:
                return ServiceResult.failure("Session is invalid or expired")

            # Update last activity
            session.last_activity = datetime.now(UTC)
            await self.session_repository.update(session)

            return ServiceResult.success(session)

        except Exception as e:
            return ServiceResult.failure(f"Session validation failed: {e!s}")

    async def refresh_session(
        self,
        session_id: str,
        duration: timedelta,
    ) -> ServiceResult[Session]:
        """Refresh a user session with new expiration time.

        Args:
            session_id: The session ID to refresh.
            duration: The new duration for the session.

        Returns:
            ServiceResult containing the refreshed Session if successful,
            or failure with error message.

        """
        try:
            # Get session
            session_result = await self.session_repository.get_by_token(session_id)
            if not session_result.is_success:
                return ServiceResult.failure("Session not found")

            session = session_result.value

            # Refresh session
            session.refresh(duration)
            await self.session_repository.update(session)

            return ServiceResult.success(session)

        except Exception as e:
            return ServiceResult.failure(f"Session refresh failed: {e!s}")


# Type aliases for dependency injection
UserRepository = Any  # Will be imported from infrastructure
TokenRepository = Any  # Will be imported from infrastructure
SessionRepository = Any  # Will be imported from infrastructure
RoleRepository = Any  # Will be imported from infrastructure
PasswordHasher = Any  # Will be imported from infrastructure
TokenGenerator = Any  # Will be imported from infrastructure
SessionGenerator = Any  # Will be imported from infrastructure
EventBus = Any  # Will be imported from infrastructure

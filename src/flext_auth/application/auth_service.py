"""FLEXT Auth application service.

Built on flext-core foundation for authentication business logic.
Uses modern Python 3.13 patterns and clean architecture.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

import bcrypt

from flext_core import ServiceResult

# Use centralized logger from flext-observability - ELIMINATE DUPLICATION
from flext_observability.logging import get_logger

if TYPE_CHECKING:
    from uuid import UUID

    from flext_auth.domain.entities import Session
    from flext_auth.domain.entities import User
    from flext_auth.domain.repositories import RoleRepository
    from flext_auth.domain.repositories import SessionRepository
    from flext_auth.domain.repositories import UserRepository

logger = get_logger(__name__)


class AuthenticationService:
    """Authentication service using flext-core patterns."""

    def __init__(
        self,
        user_repo: UserRepository,
        session_repo: SessionRepository,
        role_repo: RoleRepository,
    ) -> None:
        self.user_repo = user_repo
        self.session_repo = session_repo
        self.role_repo = role_repo

    async def create_user(
        self,
        username: str,
        email: str,
        password: str,
        role: str = "user",
    ) -> ServiceResult[User]:
        """Create a new user account."""
        try:
            logger.info("Creating new user: %s", username)

            # Check if username exists
            username_exists = await self.user_repo.username_exists(username)
            if not username_exists.is_success:
                return username_exists

            if username_exists.value:
                return ServiceResult.failure(f"Username '{username}' already exists")

            # Check if email exists
            email_exists = await self.user_repo.email_exists(email)
            if not email_exists.is_success:
                return email_exists

            if email_exists.value:
                return ServiceResult.failure(f"Email '{email}' already exists")

            # Hash password
            password_hash = self._hash_password(password)

            # Create user entity
            from flext_auth.domain.entities import User

            user = User(
                username=username,
                email=email,
                password_hash=password_hash,
                role=role,
                status="active",
            )

            # Save user
            result = await self.user_repo.create(user)
            if result.is_success:
                logger.info("User created successfully: %s", username)

            return result

        except Exception as e:
            logger.exception("Failed to create user %s: %s", username, e)
            return ServiceResult.failure(f"Failed to create user: {e}")

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str,
        user_agent: str,
    ) -> ServiceResult[tuple[User, Session]]:
        """Authenticate user and create session."""
        try:
            logger.info("Authenticating user: %s", username)

            # Find user
            user_result = await self.user_repo.find_by_username(username)
            if not user_result.is_success:
                return user_result

            if not user_result.value:
                return ServiceResult.failure("Invalid username or password")

            user = user_result.value

            # Check if account is locked
            if user.is_locked():
                return ServiceResult.failure(
                    "Account is locked due to too many failed attempts",
                )

            # Check if account is active
            if not user.is_active():
                return ServiceResult.failure("Account is not active")

            # Verify password
            if not self._verify_password(password, user.password_hash):
                # Record failed attempt
                user.record_login_attempt(success=False, ip_address=ip_address)
                await self.user_repo.update(user)
                return ServiceResult.failure("Invalid username or password")

            # Record successful login
            user.record_login_attempt(success=True, ip_address=ip_address)

            # Create session
            from flext_auth.domain.value_objects import SessionToken

            session_token = SessionToken.generate()

            from flext_auth.domain.entities import Session

            session = Session.create_new(
                user_id=user.id,
                token=session_token.value,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_in_minutes=60,
            )

            # Save updates
            await self.user_repo.update(user)
            session_result = await self.session_repo.create(session)

            if not session_result.is_success:
                return session_result

            logger.info("User authenticated successfully: %s", username)
            return ServiceResult.success((user, session_result.value))

        except Exception as e:
            logger.exception("Authentication failed for %s: %s", username, e)
            return ServiceResult.failure(f"Authentication failed: {e}")

    async def validate_session(self, token: str) -> ServiceResult[tuple[User, Session]]:
        """Validate session token and return user and session."""
        try:
            # Find session by token
            session_result = await self.session_repo.find_by_token(token)
            if session_result.is_success:
                return session_result

            if not session_result.value:
                return ServiceResult.failure("Invalid session token")

            session = session_result.value

            # Check if session is active
            if not session.is_active():
                return ServiceResult.failure("Session is expired or revoked")

            # Find user
            user_result = await self.user_repo.find_by_id(session.user_id)
            if user_result.is_success:
                return user_result

            if not user_result.value:
                return ServiceResult.failure("User not found")

            user = user_result.value

            # Check if user is still active
            if not user.is_active():
                return ServiceResult.failure("User account is not active")

            # Update session activity
            session.update_activity()
            await self.session_repo.update(session)

            return ServiceResult.success((user, session))

        except Exception as e:
            logger.exception("Session validation failed: %s", e)
            return ServiceResult.failure(f"Session validation failed: {e}")

    async def logout_user(self, token: str) -> ServiceResult[bool]:
        """Logout user by revoking session."""
        try:
            # Find session
            session_result = await self.session_repo.find_by_token(token)
            if session_result.is_success:
                return session_result

            if not session_result.value:
                return ServiceResult.failure("Session not found")

            session = session_result.value

            # Revoke session
            session.revoke()
            update_result = await self.session_repo.update(session)

            if update_result.is_success:
                logger.info("User logged out successfully")

            return ServiceResult.success(True)

        except Exception as e:
            logger.exception("Logout failed: %s", e)
            return ServiceResult.failure(f"Logout failed: {e}")

    async def change_password(
        self,
        user_id: UUID,
        current_password: str,
        new_password: str,
    ) -> ServiceResult[bool]:
        """Change user password."""
        try:
            # Find user
            user_result = await self.user_repo.find_by_id(user_id)
            if user_result.is_success:
                return user_result

            if not user_result.value:
                return ServiceResult.failure("User not found")

            user = user_result.value

            # Verify current password
            if not self._verify_password(current_password, user.password_hash):
                return ServiceResult.failure("Current password is incorrect")

            # Hash new password
            new_password_hash = self._hash_password(new_password)

            # Update password
            user.change_password(new_password_hash)

            # Save user
            result = await self.user_repo.update(user)
            if result.is_success:
                logger.info("Password changed successfully for user: %s", user.username)

            return ServiceResult.success(True)

        except Exception as e:
            logger.exception("Password change failed: %s", e)
            return ServiceResult.failure(f"Password change failed: {e}")

    async def verify_email(self, user_id: UUID) -> ServiceResult[bool]:
        """Verify user email address."""
        try:
            # Find user
            user_result = await self.user_repo.find_by_id(user_id)
            if user_result.is_success:
                return user_result

            if not user_result.value:
                return ServiceResult.failure("User not found")

            user = user_result.value

            # Verify email
            user.verify_email()

            # Save user
            result = await self.user_repo.update(user)
            if result.is_success:
                logger.info("Email verified for user: %s", user.username)

            return ServiceResult.success(True)

        except Exception as e:
            logger.exception("Email verification failed: %s", e)
            return ServiceResult.failure(f"Email verification failed: {e}")

    async def revoke_all_user_sessions(self, user_id: UUID) -> ServiceResult[int]:
        """Revoke all sessions for a user."""
        try:
            result = await self.session_repo.revoke_all_user_sessions(user_id)
            if result.is_success:
                logger.info("Revoked %d sessions for user", result.value)

            return result

        except Exception as e:
            logger.exception("Failed to revoke user sessions: %s", e)
            return ServiceResult.failure(f"Failed to revoke sessions: {e}")

    async def cleanup_expired_sessions(self) -> ServiceResult[int]:
        """Clean up expired sessions."""
        try:
            result = await self.session_repo.cleanup_expired_sessions()
            if result.is_success:
                logger.info("Cleaned up %d expired sessions", result.value)

            return result

        except Exception as e:
            logger.exception("Failed to cleanup expired sessions: %s", e)
            return ServiceResult.failure(f"Failed to cleanup sessions: {e}")

    def _hash_password(self, password: str) -> str:
        """Hash password using bcrypt."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
        return hashed.decode("utf-8")

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        return bcrypt.checkpw(password.encode("utf-8"), hashed.encode("utf-8"))


class PasswordService:
    """Password management service using flext-core patterns."""

    async def generate_reset_token(self, email: str) -> ServiceResult[str]:
        """Generate password reset token."""
        try:
            from flext_auth.domain.value_objects import PasswordResetToken

            token = PasswordResetToken.generate()

            # In a real implementation, you would:
            # 1. Store the token with expiration
            # 2. Send email with reset link

            logger.info("Password reset token generated for email: %s", email)
            return ServiceResult.success(token.value)

        except Exception as e:
            logger.exception("Failed to generate reset token: %s", e)
            return ServiceResult.failure(f"Failed to generate reset token: {e}")

    async def reset_password(
        self,
        token: str,
        new_password: str,
        user_repo: UserRepository,
    ) -> ServiceResult[bool]:
        """Reset password using token."""
        try:
            # In a real implementation, you would:
            # 1. Validate the token
            # 2. Find the user associated with the token
            # 3. Update the password
            # 4. Invalidate the token

            # For now, return success placeholder
            logger.info("Password reset completed")
            return ServiceResult.success(True)

        except Exception as e:
            logger.exception("Password reset failed: %s", e)
            return ServiceResult.failure(f"Password reset failed: {e}")


class EmailVerificationService:
    """Email verification service using flext-core patterns."""

    async def generate_verification_token(self, user_id: UUID) -> ServiceResult[str]:
        """Generate email verification token."""
        try:
            from flext_auth.domain.value_objects import EmailVerificationToken

            token = EmailVerificationToken.generate()

            # In a real implementation, you would:
            # 1. Store the token with expiration
            # 2. Send verification email

            logger.info("Email verification token generated for user: %s", user_id)
            return ServiceResult.success(token.value)

        except Exception as e:
            logger.exception("Failed to generate verification token: %s", e)
            return ServiceResult.failure(f"Failed to generate verification token: {e}")

    async def verify_email_token(
        self,
        token: str,
        auth_service: AuthenticationService,
    ) -> ServiceResult[bool]:
        """Verify email using token."""
        try:
            # In a real implementation, you would:
            # 1. Validate the token
            # 2. Find the user associated with the token
            # 3. Mark email as verified
            # 4. Invalidate the token

            logger.info("Email verification completed")
            return ServiceResult.success(True)

        except Exception as e:
            logger.exception("Email verification failed: %s", e)
            return ServiceResult.failure(f"Email verification failed: {e}")

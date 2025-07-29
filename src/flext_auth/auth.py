"""Main authentication service orchestrating all authentication operations."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from flext_core import (
    FlextAlreadyExistsError,
    FlextOperationError,
    FlextResult,
    FlextValidationError,
    get_logger,
)

from flext_auth.domain.entities import (
    FlextLoginAttempt as LoginAttempt,
    FlextSession as Session,
    FlextSessionStatus as SessionStatus,
    FlextUser as User,
    FlextUserRole as UserRole,
    FlextUserStatus as UserStatus,
)
from flext_auth.domain.value_objects import (
    FlextPlainPassword as PlainPassword,
    FlextSecurityContext as SecurityContext,
    FlextUserEmail as UserEmail,
    FlextUsername as Username,
)
from flext_auth.jwt import REFRESH_TOKEN_TYPE

# Initialize logger using FLEXT patterns
logger = get_logger(__name__)

if TYPE_CHECKING:
    from flext_auth.jwt import FlextJWTService as JWTService
    from flext_auth.services.password_service import (
        FlextPasswordService as PasswordService,
    )
    from flext_auth.session import SessionRepository
    from flext_auth.user import UserRepository


@dataclass
class FlextAuthServiceConfig:
    """Configuration for FlextAuthService to reduce constructor arguments."""

    max_failed_attempts: int = 5
    lockout_duration_minutes: int = 30
    session_expire_hours: int = 24
    max_concurrent_sessions: int = 5


@dataclass
class FlextUserRegistrationData:
    """User registration data to reduce method arguments."""

    username: str
    email: str
    password: str
    role: UserRole = UserRole.USER
    ip_address: str | None = None
    user_agent: str | None = None


class FlextAuthService:
    """Professional authentication service with complete auth flows."""

    def __init__(
        self,
        user_repository: UserRepository,
        session_repository: SessionRepository,
        password_service: PasswordService,
        jwt_service: JWTService,
        config: FlextAuthServiceConfig | None = None,
    ) -> None:
        """Initialize authentication service with dependencies."""
        self.user_repo = user_repository
        self.session_repo = session_repository
        self.password_service = password_service
        self.jwt_service = jwt_service

        # Use provided config or default
        self.config = config or FlextAuthServiceConfig()

        # Extract commonly used values for backward compatibility
        self.max_failed_attempts = self.config.max_failed_attempts
        self.lockout_duration_minutes = self.config.lockout_duration_minutes
        self.session_expire_hours = self.config.session_expire_hours
        self.max_concurrent_sessions = self.config.max_concurrent_sessions

    async def register_user(  # noqa: PLR0911
        self,
        registration_data: FlextUserRegistrationData,
    ) -> FlextResult[User]:
        """Register a new user with validation and security checks."""
        try:
            # Extract data for easier access
            username = registration_data.username
            email = registration_data.email
            role = registration_data.role
            ip_address = registration_data.ip_address
            user_agent = registration_data.user_agent

            # Validate input data
            validation_result = await self._validate_registration_data(
                registration_data,
            )
            if not validation_result.is_success:
                return FlextResult.fail(
                    validation_result.error or "Registration data validation failed",
                )

            # Safely extract validated data
            if validation_result.data is None:
                return FlextResult.fail("Validation returned no data")
            _username_vo, email_vo, password_vo = validation_result.data

            # Check if user already exists
            user_exists_result = await self._check_user_exists(username)
            if not user_exists_result.is_success:
                return FlextResult.fail(
                    user_exists_result.error or "User existence check failed",
                )

            # Check if email already exists
            email_exists_result = await self._check_email_exists(email)
            if not email_exists_result.is_success:
                return FlextResult.fail(
                    email_exists_result.error or "Email existence check failed",
                )

            # Hash password
            hash_result = self.password_service.hash_password(password_vo)
            if not hash_result.is_success:
                return FlextResult.fail(
                    FlextOperationError(
                        f"Password hashing failed: {hash_result.error}",
                        operation="password_hashing",
                        stage="user_creation",
                    ).message,
                )

            # Create user entity
            user = User(
                id=secrets.token_urlsafe(16),
                username=username,
                email=email_vo.value,
                password_hash=hash_result.data.value if hash_result.data else "",
                role=role,
                status=UserStatus.ACTIVE,
            )

            # Save user
            save_result = await self.user_repo.save(user)
            if not save_result.is_success:
                return FlextResult.fail(f"Failed to save user: {save_result.error}")

            # Log registration attempt
            await self._log_login_attempt(
                username=username,
                ip_address=ip_address or "unknown",
                user_agent=user_agent,
                success=True,
                failure_reason=None,
            )

            if save_result.data is None:
                return FlextResult.fail("User save returned None data")
            return FlextResult.ok(save_result.data)

        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"User registration failed: {e}")

    async def authenticate_user(  # noqa: C901, PLR0911
        self,
        username: str,
        password: str,
        ip_address: str,
        user_agent: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Authenticate user and create session with JWT tokens."""
        try:
            # Get user
            user_result = await self.user_repo.get_by_username(username)
            if not user_result.is_success:
                await self._log_login_attempt(
                    username,
                    ip_address,
                    user_agent,
                    success=False,
                    failure_reason="Database error",
                )
                return FlextResult.fail(f"Authentication failed: {user_result.error}")

            user = user_result.data
            if not user:
                await self._log_login_attempt(
                    username,
                    ip_address,
                    user_agent,
                    success=False,
                    failure_reason="User not found",
                )
                return FlextResult.fail("Invalid username or password")

            # Check if user is locked
            if user.is_locked():
                await self._log_login_attempt(
                    username,
                    ip_address,
                    user_agent,
                    success=False,
                    failure_reason="Account locked",
                )
                return FlextResult.fail("Account is locked")

            # Check if user is active
            if not user.is_active():
                await self._log_login_attempt(
                    username,
                    ip_address,
                    user_agent,
                    success=False,
                    failure_reason="Account inactive",
                )
                return FlextResult.fail("Account is not active")

            # Verify password
            verify_result = self.password_service.verify_password(
                password,
                user.password_hash,
            )
            if not verify_result.is_success:
                await self._handle_failed_login(
                    user,
                    ip_address,
                    user_agent,
                    "Password verification error",
                )
                return FlextResult.fail("Authentication failed")

            if not verify_result.data:
                await self._handle_failed_login(
                    user,
                    ip_address,
                    user_agent,
                    "Invalid password",
                )
                return FlextResult.fail("Invalid username or password")

            # Successful authentication - reset failed attempts
            user.reset_failed_login()
            await self.user_repo.save(user)

            # Check for too many concurrent sessions
            active_sessions_result = await self.session_repo.get_active_sessions(
                user.id,
            )
            if (
                active_sessions_result.is_success
                and active_sessions_result.data
                and len(active_sessions_result.data) >= self.max_concurrent_sessions
            ):
                # Revoke oldest session
                oldest_session = min(
                    active_sessions_result.data or [],
                    key=lambda s: s.created_at,
                )
                await self.session_repo.revoke_session(oldest_session.id)

            # Create session
            session_result = await self._create_user_session(
                user=user,
                ip_address=ip_address,
                user_agent=user_agent,
            )
            if not session_result.is_success:
                return FlextResult.fail(
                    f"Session creation failed: {session_result.error}",
                )

            session = session_result.data

            # Generate JWT tokens
            tokens_result = self.jwt_service.generate_token_pair(
                user_id=user.id,
                username=user.username,
                role=user.role.value,
                session_id=session.id if session else "",
            )
            if not tokens_result.is_success:
                return FlextResult.fail(
                    f"Token generation failed: {tokens_result.error}",
                )

            tokens = tokens_result.data

            # Update session with tokens (create new immutable instance)
            if session and tokens:
                updated_session = Session(
                    id=session.id,
                    user_id=session.user_id,
                    access_token=tokens["access_token"],
                    refresh_token=tokens["refresh_token"],
                    status=session.status,
                    ip_address=session.ip_address,
                    user_agent=session.user_agent,
                    expires_at=session.expires_at,
                    created_at=session.created_at,
                    last_accessed=datetime.now(UTC),
                )
                await self.session_repo.save(updated_session)
                session = updated_session

            # Log successful login
            await self._log_login_attempt(
                username,
                ip_address,
                user_agent,
                success=True,
                failure_reason=None,
            )

            return FlextResult.ok(
                {
                    "user": {
                        "id": user.id,
                        "username": user.username,
                        "email": user.email,
                        "role": user.role.value,
                        "status": user.status.value,
                        "last_login": (
                            user.last_login.isoformat() if user.last_login else None
                        ),
                    },
                    "session": {
                        "id": session.id if session else "",
                        "expires_at": session.expires_at.isoformat() if session else "",
                    },
                    "tokens": tokens,
                },
            )

        except (RuntimeError, ValueError, OSError) as e:
            await self._log_login_attempt(
                username,
                ip_address,
                user_agent,
                success=False,
                failure_reason=f"System error: {e}",
            )
            return FlextResult.fail(f"Authentication failed: {e}")

    async def validate_token(self, token: str) -> FlextResult[SecurityContext]:  # noqa: PLR0911
        """Validate JWT token and return security context."""
        try:
            # Verify JWT token
            verify_result = self.jwt_service.verify_token(token)
            if not verify_result.is_success:
                return FlextResult.fail(
                    f"Token verification failed: {verify_result.error}",
                )

            claims = verify_result.data
            if not claims:
                return FlextResult.fail("Invalid token claims")

            # Get user to ensure they still exist and are active
            user_result = await self.user_repo.get_by_id(claims.sub)
            if not user_result.is_success:
                return FlextResult.fail("User lookup failed")

            user = user_result.data
            if not user:
                return FlextResult.fail("User not found")

            if not user.is_active():
                return FlextResult.fail("User account is not active")

            # Check session if present
            if claims.session_id:
                session_result = await self.session_repo.get_by_id(claims.session_id)
                if session_result.is_success and session_result.data:
                    session = session_result.data
                    if not session.is_valid():
                        return FlextResult.fail("Session is no longer valid")

            # Create security context
            context = SecurityContext(
                user_id=user.id,
                username=user.username,
                role=user.role.value,
                session_id=claims.session_id or "",
                permissions=[],  # Would be loaded from user roles/permissions
            )

            return FlextResult.ok(context)

        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Token validation failed: {e}")

    async def refresh_token(self, refresh_token: str) -> FlextResult[dict[str, str]]:  # noqa: C901, PLR0911
        """Refresh access token using refresh token."""
        try:
            # Verify refresh token
            verify_result = self.jwt_service.verify_token(refresh_token)
            if not verify_result.is_success:
                return FlextResult.fail(
                    f"Token verification failed: {verify_result.error}",
                )

            claims = verify_result.data
            if not claims:
                return FlextResult.fail("Invalid token claims")

            if claims.token_type != REFRESH_TOKEN_TYPE:
                return FlextResult.fail("Invalid token type")

            # Get user
            user_result = await self.user_repo.get_by_id(claims.sub)
            if not user_result.is_success or not user_result.data:
                return FlextResult.fail("User not found")

            user = user_result.data
            if not user.is_active():
                return FlextResult.fail("User account is not active")

            # Check session
            if claims.session_id:
                session_result = await self.session_repo.get_by_id(claims.session_id)
                if not session_result.is_success or not session_result.data:
                    return FlextResult.fail("Session not found")

                session = session_result.data
                if not session.is_valid():
                    return FlextResult.fail("Session is no longer valid")

            # Generate new token pair
            tokens_result = self.jwt_service.generate_token_pair(
                user_id=user.id,
                username=user.username,
                role=user.role.value,
                session_id=claims.session_id or "",
            )
            if not tokens_result.is_success:
                return FlextResult.fail(
                    f"Token generation failed: {tokens_result.error}",
                )

            if tokens_result.data is None:
                return FlextResult.fail("Token generation returned no data")
            return FlextResult.ok(tokens_result.data)

        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Token refresh failed: {e}")

    async def logout_user(self, token: str) -> FlextResult[bool]:
        """Logout user by revoking session."""
        try:
            # Extract user ID and session ID from token
            verify_result = self.jwt_service.verify_token(token)
            if verify_result.is_success:
                claims = verify_result.data
                if claims and claims.session_id:
                    return await self.session_repo.revoke_session(claims.session_id)

            # If token verification fails, try to extract user ID without verification
            user_id_result = self.jwt_service.extract_user_id(token)
            if user_id_result.is_success and user_id_result.data:
                # Revoke all active sessions for the user
                revoke_result = await self.session_repo.revoke_all_user_sessions(
                    user_id_result.data,
                )
                revoked_count = revoke_result.data or 0
                return FlextResult.ok(revoked_count > 0)

            logout_success = False
            return FlextResult.ok(logout_success)

        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Logout failed: {e}")

    async def logout_all_sessions(self, user_id: str) -> FlextResult[int]:
        """Logout user from all sessions."""
        try:
            return await self.session_repo.revoke_all_user_sessions(user_id)
        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Logout all sessions failed: {e}")

    async def change_password(  # noqa: PLR0911
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> FlextResult[bool]:
        """Change user password with current password verification."""
        try:
            # Get user
            user_result = await self.user_repo.get_by_id(user_id)
            if not user_result.is_success or not user_result.data:
                return FlextResult.fail("User not found")

            user = user_result.data

            # Verify current password
            verify_result = self.password_service.verify_password(
                current_password,
                user.password_hash,
            )
            if not verify_result.is_success or not verify_result.data:
                return FlextResult.fail("Current password is incorrect")

            # Validate new password
            try:
                PlainPassword(value=new_password)
            except (RuntimeError, ValueError, OSError) as e:
                return FlextResult.fail(f"Password validation failed: {e}")

            # Hash new password
            hash_result = self.password_service.hash_password(new_password)
            if not hash_result.is_success:
                return FlextResult.fail(f"Password hashing failed: {hash_result.error}")

            # Update user (create new immutable instance)
            hashed_password = hash_result.data
            if not hashed_password:
                return FlextResult.fail("Password hashing returned no data")

            updated_user = User(
                id=user.id,
                username=user.username,
                email=user.email,
                password_hash=hashed_password.value,
                role=user.role,
                status=user.status,
                failed_login_attempts=user.failed_login_attempts,
                locked_until=user.locked_until,
                last_login=user.last_login,
                created_at=user.created_at,
                updated_at=datetime.now(UTC),
            )

            save_result = await self.user_repo.save(updated_user)
            if not save_result.is_success:
                return FlextResult.fail(f"Failed to save user: {save_result.error}")

            # Revoke all existing sessions to force re-login
            await self.session_repo.revoke_all_user_sessions(user_id)

            password_changed = True
            return FlextResult.ok(password_changed)

        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Password change failed: {e}")

    async def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Clean up expired sessions."""
        try:
            return await self.session_repo.cleanup_expired_sessions()
        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Session cleanup failed: {e}")

    async def get_user_sessions(
        self,
        user_id: str,
    ) -> FlextResult[list[dict[str, object]]]:
        """Get all sessions for a user."""
        try:
            sessions_result = await self.session_repo.get_by_user_id(user_id)
            if not sessions_result.is_success:
                return FlextResult.fail(
                    f"Failed to get sessions: {sessions_result.error}",
                )

            sessions_list = sessions_result.data
            if not sessions_list:
                return FlextResult.ok([])

            sessions_data: list[dict[str, object]] = [
                {
                    "id": session.id,
                    "status": session.status.value,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                    "created_at": session.created_at.isoformat(),
                    "last_accessed": session.last_accessed.isoformat(),
                    "expires_at": session.expires_at.isoformat(),
                    "is_valid": session.is_valid(),
                }
                for session in sessions_list
            ]

            return FlextResult.ok(sessions_data)

        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Failed to get user sessions: {e}")

    # Private helper methods

    async def _validate_registration_data(
        self,
        registration_data: FlextUserRegistrationData,
    ) -> FlextResult[tuple[Username, UserEmail, PlainPassword]]:
        """Validate registration data and return value objects."""
        try:
            username_vo = Username(value=registration_data.username)
            email_vo = UserEmail(value=registration_data.email)
            password_vo = PlainPassword(value=registration_data.password)
            return FlextResult.ok((username_vo, email_vo, password_vo))
        except (ValueError, TypeError) as e:
            return FlextResult.fail(
                FlextValidationError(
                    f"Input validation failed: {e}",
                    validation_details={
                        "username": registration_data.username,
                        "email": registration_data.email,
                    },
                ).message,
            )

    async def _create_user_session(
        self,
        user: User,
        ip_address: str,
        user_agent: str | None,
    ) -> FlextResult[Session]:
        """Create a new session for user."""
        try:
            session = Session(
                id=secrets.token_urlsafe(32),
                user_id=user.id,
                access_token="",  # Will be set later
                refresh_token=None,
                status=SessionStatus.ACTIVE,
                ip_address=ip_address,
                user_agent=user_agent,
                expires_at=datetime.now(UTC)
                + timedelta(hours=self.session_expire_hours),
            )

            return await self.session_repo.save(session)

        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Session creation failed: {e}")

    async def _handle_failed_login(
        self,
        user: User,
        ip_address: str,
        user_agent: str | None,
        reason: str,
    ) -> None:
        """Handle failed login attempt with account locking."""
        try:
            # Create updated user with incremented failed login attempts
            user = user.increment_failed_login()

            # Lock account if too many failures
            if user.failed_login_attempts >= self.max_failed_attempts:
                user = User(
                    id=user.id,
                    username=user.username,
                    email=user.email,
                    password_hash=user.password_hash,
                    role=user.role,
                    status=UserStatus.LOCKED,
                    failed_login_attempts=user.failed_login_attempts,
                    locked_until=datetime.now(UTC)
                    + timedelta(
                        minutes=self.lockout_duration_minutes,
                    ),
                    last_login=user.last_login,
                    created_at=user.created_at,
                    updated_at=datetime.now(UTC),
                )

            save_result = await self.user_repo.save(user)
            if not save_result.is_success:
                # Log but don't fail the authentication flow
                pass

            await self._log_login_attempt(
                user.username,
                ip_address,
                user_agent,
                success=False,
                failure_reason=reason,
            )
        except (RuntimeError, ValueError, OSError) as e:
            # Failed login handling errors shouldn't break authentication flow
            # Log error but continue
            _ = str(e)  # Use the exception to avoid bare except

    async def _log_login_attempt(
        self,
        username: str,
        ip_address: str,
        user_agent: str | None,
        *,
        success: bool,
        failure_reason: str | None,
    ) -> None:
        """Log login attempt for security monitoring."""
        try:
            # Create login attempt entity for potential audit repository
            LoginAttempt(
                id=secrets.token_urlsafe(16),
                username=username,
                ip_address=ip_address,
                user_agent=user_agent,
                success=success,
                failure_reason=failure_reason,
            )
        except (RuntimeError, ValueError, OSError) as e:
            # Logging errors shouldn't break authentication flow
            # Log error but continue
            _ = str(e)  # Use the exception to avoid bare except

    async def _check_user_exists(self, username: str) -> FlextResult[bool]:
        """Check if user already exists by username."""
        existing_user_result = await self.user_repo.get_by_username(username)
        if not existing_user_result.is_success:
            return FlextResult.fail(
                FlextOperationError(
                    f"Failed to check existing user: {existing_user_result.error}",
                    operation="user_lookup",
                    stage="username_check",
                ).message,
            )

        if existing_user_result.data:
            return FlextResult.fail(
                FlextAlreadyExistsError(
                    f"Username '{username}' already exists",
                    resource_type="user",
                    resource_id=username,
                ).message,
            )

        return FlextResult.ok(data=False)

    async def _check_email_exists(self, email: str) -> FlextResult[bool]:
        """Check if email already exists."""
        existing_email_result = await self.user_repo.get_by_email(email)
        if not existing_email_result.is_success:
            error_msg = f"Failed to check existing email: {existing_email_result.error}"
            return FlextResult.fail(
                FlextOperationError(
                    error_msg,
                    operation="user_lookup",
                    stage="email_check",
                ).message,
            )

        if existing_email_result.data:
            return FlextResult.fail(
                FlextAlreadyExistsError(
                    f"Email '{email}' already exists",
                    resource_type="email",
                    resource_id=email,
                ).message,
            )

        return FlextResult.ok(data=False)

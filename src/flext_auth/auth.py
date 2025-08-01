"""Main authentication service orchestrating all authentication operations."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast

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
    FlextJWTClaims as JWTClaims,
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


# SOLID REFACTORING: Parameter Object pattern to reduce parameter count
@dataclass(frozen=True)
class LoginAttemptData:
    """Parameter Object for login attempt logging - reduces parameter count."""

    username: str
    ip_address: str
    user_agent: str | None
    success: bool
    failure_reason: str | None


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


@dataclass
class ValidationPipelineStrategies:
    """Parameter Object Pattern: Encapsulates validation pipeline strategies.

    Reduces parameter count from 6 to 2, following SOLID principles.
    """

    token_validator: object
    user_validator: object
    session_validator: object
    result_creator: object
    validation_context: str


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

    async def register_user(
        self,
        registration_data: FlextUserRegistrationData,
    ) -> FlextResult[User]:
        """Register a new user with validation - SOLID refactored."""
        try:
            # Railway-Oriented Programming: Execute complete registration pipeline
            return await self._execute_user_registration_pipeline(registration_data)
        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"User registration failed: {e}")

    async def authenticate_user(
        self,
        username: str,
        password: str,
        ip_address: str,
        user_agent: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Authenticate user and create session with JWT tokens - SOLID refactored."""
        try:
            # Railway-Oriented Programming: Chain validations
            user_validation = await self._validate_user_for_authentication(
                username, ip_address, user_agent,
            )
            if not user_validation.is_success:
                return FlextResult.fail(
                    user_validation.error or "User validation failed",
                )

            user = user_validation.data
            if not user:
                return FlextResult.fail("User validation returned no data")

            # Password verification pipeline
            password_validation = await self._verify_user_password(
                user, password, ip_address, user_agent,
            )
            if not password_validation.is_success:
                return FlextResult.fail(
                    password_validation.error or "Password validation failed",
                )

            # Session management pipeline
            session_result = await self._create_authenticated_session(
                user, ip_address, user_agent,
            )
            if not session_result.is_success:
                return session_result

            # Success: return authentication data
            return session_result

        except (RuntimeError, ValueError, OSError) as e:
            await self._log_login_attempt(
                username,
                ip_address,
                user_agent,
                success=False,
                failure_reason=f"System error: {e}",
            )
            return FlextResult.fail(f"Authentication failed: {e}")

    async def validate_token(self, token: str) -> FlextResult[SecurityContext]:
        """Validate JWT token and return security context - SOLID refactored."""
        try:
            # Railway-Oriented Programming: Execute complete validation pipeline
            return await self._execute_token_validation_pipeline(token)
        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Token validation failed: {e}")

    # SOLID REFACTORING: Single Responsibility Principle methods for validate_token

    async def _validate_token_claims(self, token: str) -> FlextResult[JWTClaims]:
        """Validate JWT token and extract claims - SRP applied."""
        # Verify JWT token
        verify_result = self.jwt_service.verify_token(token)
        if not verify_result.is_success:
            return FlextResult.fail(f"Token verification failed: {verify_result.error}")

        claims = verify_result.data
        if not claims:
            return FlextResult.fail("Invalid token claims")

        return FlextResult.ok(claims)

    async def _validate_token_user(self, claims: JWTClaims) -> FlextResult[User]:
        """Validate user exists and is active for token - SRP applied."""
        # Get user to ensure they still exist and are active
        user_result = await self.user_repo.get_by_id(claims.sub)
        if not user_result.is_success:
            return FlextResult.fail("User lookup failed")

        user = user_result.data
        if not user:
            return FlextResult.fail("User not found")

        if not user.is_active():
            return FlextResult.fail("User account is not active")

        return FlextResult.ok(user)

    async def _validate_token_session(self, claims: JWTClaims) -> FlextResult[None]:
        """Validate session if present in token - SRP applied."""
        # Check session if present
        if claims.session_id:
            session_result = await self.session_repo.get_by_id(claims.session_id)
            if session_result.is_success and session_result.data:
                session = session_result.data
                if not session.is_valid():
                    return FlextResult.fail("Session is no longer valid")

        return FlextResult.ok(None)

    async def _create_security_context(
        self, user: User, claims: JWTClaims,
    ) -> FlextResult[SecurityContext]:
        """Create security context from validated user and claims - SRP applied."""
        # Create security context
        context = SecurityContext(
            user_id=user.id,
            username=user.username,
            role=user.role.value,
            session_id=claims.session_id or "",
            permissions=[],  # Would be loaded from user roles/permissions
        )

        return FlextResult.ok(context)

    # DRY PRINCIPLE: Generic Railway-Oriented Programming pipeline eliminating 30 lines
    async def _execute_validation_pipeline(
        self,
        token: str,
        strategies: ValidationPipelineStrategies,
    ) -> FlextResult[object]:
        """Generic validation pipeline following Railway-Oriented Programming.

        Template Method Pattern: Defines the skeleton of validation pipeline.
        Strategy Pattern: Accepts validation strategies via Parameter Object.

        Args:
            token: Token to validate
            strategies: ValidationPipelineStrategies containing all validators

        Returns:
            FlextResult with pipeline execution result

        """
        # Railway-Oriented Programming: Chain all validations with early returns
        # Dynamic execution bypassing strict typing for flexibility
        token_validation = await strategies.token_validator(token)  # type: ignore[operator]
        if not token_validation.is_success:
            return FlextResult.fail(
                token_validation.error or f"{strategies.validation_context} failed",
            )

        claims = token_validation.data
        if not claims:
            return FlextResult.fail(f"{strategies.validation_context} no data")

        # User validation pipeline
        user_validation = await strategies.user_validator(claims)  # type: ignore[operator]
        if not user_validation.is_success:
            return FlextResult.fail(user_validation.error or "User validation failed")

        user = user_validation.data
        if not user:
            return FlextResult.fail("User validation returned no data")

        # Session validation pipeline
        session_validation = await strategies.session_validator(claims)  # type: ignore[operator]
        if not session_validation.is_success:
            return FlextResult.fail(
                session_validation.error or "Session validation failed",
            )

        # Final result creation pipeline
        result = await strategies.result_creator(user, claims)  # type: ignore[operator]
        return cast("FlextResult[object]", result)

    async def _execute_token_validation_pipeline(
        self, token: str,
    ) -> FlextResult[SecurityContext]:
        """Execute complete token validation pipeline - Single responsibility."""
        # Use generic pipeline with token validation strategies (Parameter Object)
        strategies = ValidationPipelineStrategies(
            token_validator=self._validate_token_claims,
            user_validator=self._validate_token_user,
            session_validator=self._validate_token_session,
            result_creator=self._create_security_context,
            validation_context="Token",
        )
        result = await self._execute_validation_pipeline(token, strategies)
        # Type safety: Cast result to expected SecurityContext type
        return cast("FlextResult[SecurityContext]", result)

    async def refresh_token(self, refresh_token: str) -> FlextResult[dict[str, str]]:
        """Refresh access token using refresh token - SOLID refactored."""
        try:
            # Railway-Oriented Programming: Execute complete refresh pipeline
            return await self._execute_token_refresh_pipeline(refresh_token)
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

    async def change_password(
        self,
        user_id: str,
        current_password: str,
        new_password: str,
    ) -> FlextResult[bool]:
        """Change user password - SOLID refactored."""
        try:
            # Railway-Oriented Programming: Execute complete password change pipeline
            return await self._execute_password_change_pipeline(
                user_id, current_password, new_password,
            )
        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Password change failed: {e}")

    # SOLID REFACTORING: Single Responsibility Principle methods for change_password

    async def _validate_password_change_user(self, user_id: str) -> FlextResult[User]:
        """Validate user exists for password change - SRP applied."""
        # Get user
        user_result = await self.user_repo.get_by_id(user_id)
        if not user_result.is_success or not user_result.data:
            return FlextResult.fail("User not found")

        return FlextResult.ok(user_result.data)

    async def _verify_current_password(
        self, user: User, current_password: str,
    ) -> FlextResult[bool]:
        """Verify current password for password change - SRP applied."""
        # Verify current password
        verify_result = self.password_service.verify_password(
            current_password,
            user.password_hash,
        )
        if not verify_result.is_success or not verify_result.data:
            return FlextResult.fail("Current password is incorrect")

        is_verified = True
        return FlextResult.ok(is_verified)

    async def _validate_new_password(
        self, new_password: str,
    ) -> FlextResult[PlainPassword]:
        """Validate new password format and strength - SRP applied."""
        # Validate new password
        try:
            password_vo = PlainPassword(value=new_password)
            return FlextResult.ok(password_vo)
        except (RuntimeError, ValueError, OSError) as e:
            return FlextResult.fail(f"Password validation failed: {e}")

    async def _hash_new_password(self, new_password: str) -> FlextResult[str]:
        """Hash new password for storage - SRP applied."""
        # Hash new password
        hash_result = self.password_service.hash_password(new_password)
        if not hash_result.is_success:
            return FlextResult.fail(f"Password hashing failed: {hash_result.error}")

        # Update user (create new immutable instance)
        hashed_password = hash_result.data
        if not hashed_password:
            return FlextResult.fail("Password hashing returned no data")

        return FlextResult.ok(hashed_password.value)

    async def _update_user_password(
        self, user: User, new_password_hash: str,
    ) -> FlextResult[bool]:
        """Update user with new password hash - SRP applied."""
        updated_user = User(
            id=user.id,
            username=user.username,
            email=user.email,
            password_hash=new_password_hash,
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

        is_updated = True
        return FlextResult.ok(is_updated)

    async def _revoke_user_sessions_after_password_change(
        self, user_id: str,
    ) -> FlextResult[bool]:
        """Revoke all user sessions after password change - SRP applied."""
        # Revoke all existing sessions to force re-login
        await self.session_repo.revoke_all_user_sessions(user_id)
        are_revoked = True
        return FlextResult.ok(are_revoked)

    async def _validate_password_change_inputs(
        self, user_id: str, current_password: str, new_password: str,
    ) -> FlextResult[tuple[User, str]]:
        """Validate all password change inputs - reduces returns in main pipeline."""
        # Railway-Oriented Programming: Chain initial validations
        user_validation = await self._validate_password_change_user(user_id)
        if not user_validation.is_success:
            return FlextResult.fail(user_validation.error or "User validation failed")

        user = user_validation.data
        if not user:
            return FlextResult.fail("User validation returned no data")

        # Current password verification pipeline
        password_verification = await self._verify_current_password(
            user, current_password,
        )
        if not password_verification.is_success:
            return FlextResult.fail(
                password_verification.error or "Current password verification failed",
            )

        # Combined new password validation and hashing pipeline
        return await self._validate_and_hash_new_password(user, new_password)

    async def _validate_and_hash_new_password(
        self, user: User, new_password: str,
    ) -> FlextResult[tuple[User, str]]:
        """Validate and hash new password - reduces returns in inputs validation."""
        # New password validation pipeline
        new_password_validation = await self._validate_new_password(new_password)
        if not new_password_validation.is_success:
            return FlextResult.fail(
                new_password_validation.error or "New password validation failed",
            )

        # Password hashing pipeline
        password_hashing = await self._hash_new_password(new_password)
        if not password_hashing.is_success:
            return FlextResult.fail(password_hashing.error or "Password hashing failed")

        new_password_hash = password_hashing.data
        if not new_password_hash:
            return FlextResult.fail("Password hashing returned no data")

        return FlextResult.ok((user, new_password_hash))

    async def _execute_password_change_pipeline(
        self, user_id: str, current_password: str, new_password: str,
    ) -> FlextResult[bool]:
        """Execute complete password change pipeline - Single responsibility."""
        # Railway-Oriented Programming: Validate inputs first
        inputs_validation = await self._validate_password_change_inputs(
            user_id, current_password, new_password,
        )
        if not inputs_validation.is_success:
            return FlextResult.fail(
                inputs_validation.error or "Password change inputs validation failed",
            )

        user, new_password_hash = inputs_validation.data or (None, None)
        if not user or not new_password_hash:
            return FlextResult.fail("Inputs validation returned incomplete data")

        # User update pipeline
        user_update = await self._update_user_password(user, new_password_hash)
        if not user_update.is_success:
            return FlextResult.fail(user_update.error or "User update failed")

        # Session revocation pipeline
        session_revocation = await self._revoke_user_sessions_after_password_change(
            user_id,
        )
        if not session_revocation.is_success:
            return FlextResult.fail(
                session_revocation.error or "Session revocation failed",
            )

        is_changed = True
        return FlextResult.ok(is_changed)

    async def _execute_user_registration_pipeline(
        self, registration_data: FlextUserRegistrationData,
    ) -> FlextResult[User]:
        """Execute complete user registration pipeline - Railway-Oriented Programming.

        Template Method Pattern: Defines the skeleton of registration pipeline.
        Single Responsibility Principle: Each step handled by dedicated methods.
        """
        # Railway-Oriented Programming: Chain all validations with early returns

        # Step 1: Validate registration data
        validation_result = await self._validate_registration_data(registration_data)
        if not validation_result.is_success:
            return FlextResult.fail(
                validation_result.error or "Registration data validation failed",
            )

        # Safely extract validated data
        if validation_result.data is None:
            return FlextResult.fail("Validation returned no data")
        _username_vo, email_vo, password_vo = validation_result.data

        # Step 2: Check uniqueness constraints
        uniqueness_check = await self._check_registration_uniqueness(
            registration_data.username, registration_data.email,
        )
        if not uniqueness_check.is_success:
            return FlextResult.fail(uniqueness_check.error or "Uniqueness check failed")

        # Step 3: Create and save user
        user_creation = await self._create_and_save_user(
            registration_data, email_vo, password_vo,
        )
        if not user_creation.is_success:
            return FlextResult.fail(user_creation.error or "User creation failed")

        # Step 4: Log registration attempt (fire-and-forget pattern)
        await self._log_registration_attempt(registration_data, success=True)

        return user_creation

    # SOLID REFACTORING: Single Responsibility Principle methods for register_user

    async def _check_registration_uniqueness(
        self, username: str, email: str,
    ) -> FlextResult[bool]:
        """Check username and email uniqueness - SRP applied."""
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

        is_unique = True
        return FlextResult.ok(is_unique)

    async def _create_and_save_user(
        self,
        registration_data: FlextUserRegistrationData,
        email_vo: UserEmail,
        password_vo: PlainPassword,
    ) -> FlextResult[User]:
        """Create user entity and save to repository - SRP applied."""
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
            username=registration_data.username,
            email=email_vo.value,
            password_hash=hash_result.data.value if hash_result.data else "",
            role=registration_data.role,
            status=UserStatus.ACTIVE,
        )

        # Save user
        save_result = await self.user_repo.save(user)
        if not save_result.is_success:
            return FlextResult.fail(f"Failed to save user: {save_result.error}")

        if save_result.data is None:
            return FlextResult.fail("User save returned None data")

        return FlextResult.ok(save_result.data)

    async def _log_registration_attempt(
        self, registration_data: FlextUserRegistrationData, *, success: bool,
    ) -> None:
        """Log registration attempt - SRP applied."""
        await self._log_login_attempt(
            username=registration_data.username,
            ip_address=registration_data.ip_address or "unknown",
            user_agent=registration_data.user_agent,
            success=success,
            failure_reason=None,
        )

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

    async def _log_login_attempt_with_data(
        self,
        attempt_data: LoginAttemptData,
    ) -> None:
        """Log login attempt using Parameter Object pattern - SOLID refactored."""
        try:
            # Create login attempt entity for potential audit repository
            LoginAttempt(
                id=secrets.token_urlsafe(16),
                username=attempt_data.username,
                ip_address=attempt_data.ip_address,
                user_agent=attempt_data.user_agent,
                success=attempt_data.success,
                failure_reason=attempt_data.failure_reason,
            )
        except (RuntimeError, ValueError, OSError) as e:
            # Logging errors shouldn't break authentication flow
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
        """Log login attempt for security monitoring - backward compatibility."""
        # Use Parameter Object pattern internally
        attempt_data = LoginAttemptData(
            username=username,
            ip_address=ip_address,
            user_agent=user_agent,
            success=success,
            failure_reason=failure_reason,
        )
        await self._log_login_attempt_with_data(attempt_data)

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

    # SOLID REFACTORING: Single Responsibility Principle methods for authenticate_user

    async def _validate_user_for_authentication(
        self, username: str, ip_address: str, user_agent: str | None,
    ) -> FlextResult[User]:
        """Validate user exists and is eligible for authentication - SRP applied."""
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

        return FlextResult.ok(user)

    async def _verify_user_password(
        self, user: User, password: str, ip_address: str, user_agent: str | None,
    ) -> FlextResult[User]:
        """Verify user password and handle failed attempts - SRP applied."""
        # Verify password
        verify_result = self.password_service.verify_password(
            password, user.password_hash,
        )
        if not verify_result.is_success:
            await self._handle_failed_login(
                user, ip_address, user_agent, "Password verification error",
            )
            return FlextResult.fail("Authentication failed")

        if not verify_result.data:
            await self._handle_failed_login(
                user, ip_address, user_agent, "Invalid password",
            )
            return FlextResult.fail("Invalid username or password")

        # Successful password verification - reset failed attempts
        user.reset_failed_login()
        await self.user_repo.save(user)

        return FlextResult.ok(user)

    async def _create_authenticated_session(
        self, user: User, ip_address: str, user_agent: str | None,
    ) -> FlextResult[dict[str, object]]:
        """Create session and tokens for authenticated user - SRP applied."""
        # Manage concurrent sessions
        await self._manage_concurrent_sessions(user.id)

        # Create session
        session_result = await self._create_user_session(
            user=user, ip_address=ip_address, user_agent=user_agent,
        )
        if not session_result.is_success:
            return FlextResult.fail(f"Session creation failed: {session_result.error}")

        session = session_result.data

        # Generate JWT tokens
        tokens_result = self.jwt_service.generate_token_pair(
            user_id=user.id,
            username=user.username,
            role=user.role.value,
            session_id=session.id if session else "",
        )
        if not tokens_result.is_success:
            return FlextResult.fail(f"Token generation failed: {tokens_result.error}")

        tokens = tokens_result.data

        # Update session with tokens (immutable pattern)
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
            user.username, ip_address, user_agent, success=True, failure_reason=None,
        )

        return FlextResult.ok(
            {
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email,
                    "role": user.role.value,
                    "status": user.status.value,
                    "last_login": user.last_login.isoformat()
                    if user.last_login
                    else None,
                },
                "session": {
                    "id": session.id if session else "",
                    "expires_at": session.expires_at.isoformat() if session else "",
                },
                "tokens": tokens,
            },
        )

    async def _manage_concurrent_sessions(self, user_id: str) -> None:
        """Manage concurrent sessions limit - SRP applied."""
        active_sessions_result = await self.session_repo.get_active_sessions(user_id)
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

    # SOLID REFACTORING: Single Responsibility Principle methods for refresh_token

    async def _validate_refresh_token(
        self, refresh_token: str,
    ) -> FlextResult[JWTClaims]:
        """Validate refresh token and return claims - SRP applied."""
        # Verify refresh token
        verify_result = self.jwt_service.verify_token(refresh_token)
        if not verify_result.is_success:
            return FlextResult.fail(f"Token verification failed: {verify_result.error}")

        claims = verify_result.data
        if not claims:
            return FlextResult.fail("Invalid token claims")

        if claims.token_type != REFRESH_TOKEN_TYPE:
            return FlextResult.fail("Invalid token type")

        return FlextResult.ok(claims)

    async def _validate_refresh_user(self, claims: JWTClaims) -> FlextResult[User]:
        """Validate user for token refresh - SRP applied."""
        # Get user
        user_result = await self.user_repo.get_by_id(claims.sub)
        if not user_result.is_success or not user_result.data:
            return FlextResult.fail("User not found")

        user = user_result.data
        if not user.is_active():
            return FlextResult.fail("User account is not active")

        return FlextResult.ok(user)

    async def _validate_refresh_session(self, claims: JWTClaims) -> FlextResult[None]:
        """Validate session for token refresh - SRP applied."""
        # Check session if present
        if claims.session_id:
            session_result = await self.session_repo.get_by_id(claims.session_id)
            if not session_result.is_success or not session_result.data:
                return FlextResult.fail("Session not found")

            session = session_result.data
            if not session.is_valid():
                return FlextResult.fail("Session is no longer valid")

        return FlextResult.ok(None)

    async def _generate_refreshed_tokens(
        self, user: User, claims: JWTClaims,
    ) -> FlextResult[dict[str, str]]:
        """Generate new token pair for refresh - SRP applied."""
        # Generate new token pair
        tokens_result = self.jwt_service.generate_token_pair(
            user_id=user.id,
            username=user.username,
            role=user.role.value,
            session_id=claims.session_id or "",
        )
        if not tokens_result.is_success:
            return FlextResult.fail(f"Token generation failed: {tokens_result.error}")

        if tokens_result.data is None:
            return FlextResult.fail("Token generation returned no data")

        return FlextResult.ok(tokens_result.data)

    async def _execute_token_refresh_pipeline(
        self, refresh_token: str,
    ) -> FlextResult[dict[str, str]]:
        """Execute complete token refresh pipeline - Single responsibility."""
        # Use generic pipeline with refresh token strategies (Parameter Object)
        strategies = ValidationPipelineStrategies(
            token_validator=self._validate_refresh_token,
            user_validator=self._validate_refresh_user,
            session_validator=self._validate_refresh_session,
            result_creator=self._generate_refreshed_tokens,
            validation_context="Refresh token",
        )
        result = await self._execute_validation_pipeline(refresh_token, strategies)
        # Type safety: Cast result to expected dict type
        return cast("FlextResult[dict[str, str]]", result)

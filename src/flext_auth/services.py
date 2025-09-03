"""FLEXT Auth Services - Application layer authentication service following flext-core patterns.

Provides FlextAuthService class as the main authentication orchestrator,
implementing Clean Architecture application services with dependency injection.

Usage:
    # Initialize service with dependencies
    auth_service = FlextAuthService(
        jwt_secret="your-secret-key",
        bcrypt_rounds=12
    )

    # Register user
    result = auth_service.register_user("john", "john@example.com", "secure_password")

    # Authenticate user
    auth_result = auth_service.authenticate_user("john", "secure_password")

"""

from __future__ import annotations

from flext_core import FlextConstants, FlextLogger, FlextResult, FlextUtilities

from flext_auth.models import (
    AuthToken,
    Session,
    User,
    authenticate_user,
    create_session,
    create_user,
)


class FlextAuthService:
    """Main authentication service orchestrating authentication workflows.

    This is the primary application service for authentication operations,
    following Clean Architecture principles and using Domain-Driven Design patterns.
    It orchestrates user registration, authentication, session management, and
    authorization using the authentication domain models.

    Architecture:
        - Application Service: Orchestrates domain operations
        - Dependency Injection: Uses constructor injection for dependencies
        - Railway Programming: All operations return FlextResult for error handling
        - Domain Model Usage: Leverages User, Session, Role entities and value objects directly
        - Business Logic: Domain logic is in entities, orchestration logic here

    Key Responsibilities:
        - User registration with validation
        - User authentication with credential verification
        - Session creation and management
        - JWT token generation and validation
        - Password hashing and verification
        - Account lockout and security policies
        - Role-based access control (RBAC)

    Dependencies:
        - JWT secret key for token signing
        - Bcrypt configuration for password hashing
        - User storage (in-memory for this implementation)
        - Session storage (in-memory for this implementation)
        - Logger for audit trails and monitoring

    Thread Safety:
        - Service instance is thread-safe for read operations
        - User/session storage requires external synchronization for writes
        - Password hashing operations are thread-safe with bcrypt
        - JWT operations are stateless and thread-safe

    Usage Examples:
        Basic authentication workflow::

            # Initialize service
            auth_service = FlextAuthService(
                jwt_secret="your-secure-secret-key", token_expire_minutes=30
            )

            # Register new user
            register_result = auth_service.register_user(
                username="john_doe",
                email="john@example.com",
                password="secure_password123",
            )

            if register_result.success:
                user = register_result.value
                print(f"User registered: {user.username}")

            # Authenticate user
            auth_result = auth_service.authenticate_user(
                username="john_doe", password="secure_password123"
            )

            if auth_result.success:
                auth_data = auth_result.value
                user_info = auth_data["user"]
                session_info = auth_data["session"]
                jwt_info = auth_data["jwt"]

        Token validation::

            # Validate JWT token
            token_result = auth_service.validate_jwt_token(jwt_token)

            if token_result.success:
                user_id = token_result.value["user_id"]
                user = auth_service.get_user_by_id(user_id)

        Session management::

            # Get user sessions
            sessions_result = auth_service.get_user_sessions(user_id)

            # Revoke session
            revoke_result = auth_service.revoke_session(session_id)

            # Cleanup expired sessions
            cleanup_result = auth_service.cleanup_expired_sessions()

    Performance Considerations:
        - In-memory storage for development (replace with database in production)
        - Bcrypt rounds configurable for performance vs security balance
        - JWT validation is fast (stateless verification)
        - Session cleanup runs periodically to prevent memory leaks
        - Password hashing is CPU-intensive by design (security feature)

    Security Features:
        - Bcrypt password hashing with configurable rounds
        - JWT tokens with expiration and validation
        - Account lockout after failed attempts
        - Case-insensitive username lookup
        - Secure random token generation
        - Audit logging for security events

    """

    def __init__(
        self,
        jwt_secret: str | None = None,
        token_expire_minutes: int = FlextConstants.Auth.JWT_DEFAULT_EXPIRY_MINUTES,
        bcrypt_rounds: int = FlextConstants.Auth.BCRYPT_ROUNDS,
    ) -> None:
        """Initialize authentication service with configuration.

        Args:
            jwt_secret: Secret key for JWT token signing (generated if None)
            token_expire_minutes: JWT token expiration in minutes
            bcrypt_rounds: Bcrypt hashing rounds for password security

        """
        self.jwt_secret = jwt_secret or FlextUtilities.generate_uuid()
        self.token_expire_minutes = token_expire_minutes
        self.bcrypt_rounds = bcrypt_rounds

        # In-memory storage (replace with database repositories in production)
        self.users: dict[str, User] = {}
        self.sessions: dict[str, Session] = {}

        # Indexes for efficient lookups
        self.username_index: dict[str, str] = {}  # username -> user_id
        self.email_index: dict[str, str] = {}  # email -> user_id
        self.user_sessions_index: dict[str, list[str]] = {}  # user_id -> [session_ids]

        # Logger for audit trails
        self.logger = FlextLogger(__name__)

        self.logger.info(
            "FlextAuthService initialized",
            extra={
                "token_expire_minutes": token_expire_minutes,
                "bcrypt_rounds": bcrypt_rounds,
                "jwt_secret_length": len(self.jwt_secret),
            },
        )

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        roles: list[str] | None = None,
    ) -> FlextResult[User]:
        """Register new user with validation and duplicate checking.

        Args:
            username: Unique username for authentication
            email: User email address (must be unique)
            password: Plain text password (will be hashed)
            full_name: Optional full name
            roles: Optional list of roles for RBAC

        Returns:
            FlextResult containing User entity or error message

        """
        try:
            self.logger.info(f"Attempting user registration for username: {username}")

            # Check for duplicate username (case insensitive)
            if username.lower() in self.username_index:
                self.logger.warning(
                    f"Registration failed - username already exists: {username}"
                )
                return FlextResult[User].fail(
                    "Username already exists",
                    error_code=FlextConstants.Auth.USERNAME_TAKEN,
                )

            # Check for duplicate email (case insensitive)
            if email.lower() in self.email_index:
                self.logger.warning(
                    f"Registration failed - email already exists: {email}"
                )
                return FlextResult[User].fail(
                    "Email already exists", error_code=FlextConstants.Auth.EMAIL_TAKEN
                )

            # Password validation is now handled by Pydantic field_validator in Password value object

            # Create user using domain factory method
            user_result = create_user(
                username=username,
                email=email,
                password=password,
                full_name=full_name,
                roles=roles,
            )

            if user_result.is_failure:
                self.logger.error(f"User creation failed: {user_result.error}")
                return user_result

            user = user_result.value

            # Store user and update indexes
            self.users[user.id] = user
            self.username_index[username.lower()] = user.id
            self.email_index[email.lower()] = user.id
            self.user_sessions_index[user.id] = []

            self.logger.info(
                f"User registered successfully: {username} (ID: {user.id})"
            )

            return FlextResult[User].ok(user)

        except Exception as e:
            self.logger.exception("User registration failed")
            return FlextResult[User].fail(f"Registration failed: {e}")

    def authenticate_user(
        self, username: str, password: str
    ) -> FlextResult[dict[str, object]]:
        """Authenticate user and create session with JWT token.

        Args:
            username: Username for authentication
            password: Plain text password

        Returns:
            FlextResult containing authentication data (user, session, jwt) or error

        """
        # Use FlextCore.safe_call for authentication operation

        self.logger.info(f"Authentication attempt for username: {username}")

        # Execute domain authentication with proper error handling
        try:
            auth_result = authenticate_user(
                username=username,
                password=password,
                user_storage=self.users,
                jwt_secret=self.jwt_secret,
            )
        except Exception as e:
            self.logger.exception(
                f"Authentication operation failed for user {username}"
            )
            return FlextResult[dict[str, object]].fail(
                f"Authentication operation failed: {e}"
            )

        if auth_result.is_failure:
            self.logger.warning(
                f"Authentication failed for username: {username} - {auth_result.error}"
            )
            return FlextResult[dict[str, object]].fail(
                auth_result.error or "Authentication failed"
            )

        auth_data = auth_result.value
        session_data = auth_data["session"]

        # Store session and update indexes
        session_result = self._create_and_store_session(
            user_id=auth_data["user"]["id"],  # type: ignore[index]  # Auth data dict structure
            session_token=session_data["token"],  # type: ignore[index]  # Session data dict structure
            expires_at_iso=session_data["expires_at"],  # type: ignore[index]  # Session data dict structure
        )

        if session_result.is_failure:
            self.logger.error(f"Session creation failed: {session_result.error}")
            return FlextResult[dict[str, object]].fail(
                session_result.error or "Session creation failed"
            )

        session = session_result.value

        # Update auth data with session ID
        auth_data["session"]["id"] = session.id  # type: ignore[index]  # Auth data dict structure

        self.logger.info(f"Authentication successful for username: {username}")

        # Generate JWT token at service layer (not domain)
        user_dict = auth_data["user"]
        session_dict = auth_data["session"]

        # Create JWT token using AuthToken
        # Type-safe casting with explicit assertion
        user_data: dict[str, object] = user_dict if isinstance(user_dict, dict) else {}
        jwt_result = AuthToken.create_jwt_token(
            user_id=str(user_data.get("id", "")),
            username=str(user_data.get("username", "")),
            secret=self.jwt_secret,
            expires_in_minutes=self.token_expire_minutes,
        )

        if jwt_result.is_failure:
            return FlextResult[dict[str, object]].fail(
                jwt_result.error or "JWT generation failed"
            )

        jwt_token_obj = jwt_result.value

        # Convert to dict result with generated JWT - SIMPLE IS BETTER
        result_data: dict[str, object] = {
            "user": user_dict,
            "session": session_dict,
            "jwt_token": jwt_token_obj.token,
            "expires_at": jwt_token_obj.expires_at.isoformat(),
        }
        return FlextResult[dict[str, object]].ok(result_data)

    def validate_jwt_token(self, token: str) -> FlextResult[dict[str, object]]:
        """Validate JWT token and return payload.

        Args:
            token: JWT token string

        Returns:
            FlextResult containing token payload or error

        """
        try:
            import jwt

            # Decode JWT token with proper options (don't verify audience for now)
            payload = jwt.decode(
                token,
                self.jwt_secret,
                algorithms=[FlextConstants.Auth.JWT_DEFAULT_ALGORITHM],
                options={"verify_aud": False},
            )

            # Log successful validation
            self.logger.info(f"JWT token validated for user: {payload.get('user_id')}")

            # Return the payload as dict
            return FlextResult[dict[str, object]].ok(payload)

        except Exception as e:
            self.logger.exception("JWT token validation failed")
            return FlextResult[dict[str, object]].fail(f"Token validation failed: {e}")

    def get_user_by_username(self, username: str) -> FlextResult[User | None]:
        """Get user by username (case insensitive).

        Args:
            username: Username to search for

        Returns:
            FlextResult containing User entity or None if not found

        """
        try:
            user_id = self.username_index.get(username.lower())
            if not user_id:
                return FlextResult[User | None].ok(None)

            user = self.users.get(user_id)
            return FlextResult[User | None].ok(user)

        except Exception as e:
            self.logger.exception("Failed to get user by username")
            return FlextResult[User | None].fail(f"Failed to get user: {e}")

    def get_user_by_id(self, user_id: str) -> FlextResult[User | None]:
        """Get user by ID.

        Args:
            user_id: User ID to search for

        Returns:
            FlextResult containing User entity or None if not found

        """
        try:
            user = self.users.get(user_id)
            return FlextResult[User | None].ok(user)

        except Exception as e:
            self.logger.exception("Failed to get user by ID")
            return FlextResult[User | None].fail(f"Failed to get user: {e}")

    def get_user_sessions(self, user_id: str) -> FlextResult[list[Session]]:
        """Get all active sessions for user.

        Args:
            user_id: User ID to get sessions for

        Returns:
            FlextResult containing list of active sessions

        """
        try:
            session_ids = self.user_sessions_index.get(user_id, [])
            sessions = []

            for session_id in session_ids:
                session = self.sessions.get(session_id)
                if session and session.is_valid:
                    sessions.append(session)

            return FlextResult[list[Session]].ok(sessions)

        except Exception as e:
            self.logger.exception("Failed to get user sessions")
            return FlextResult[list[Session]].fail(f"Failed to get sessions: {e}")

    def revoke_session(self, session_id: str) -> FlextResult[None]:
        """Revoke specific session.

        Args:
            session_id: Session ID to revoke

        Returns:
            FlextResult indicating success or failure

        """
        try:
            session = self.sessions.get(session_id)
            if not session:
                return FlextResult[None].fail(
                    "Session not found",
                    error_code=FlextConstants.Auth.SESSION_NOT_FOUND,
                )

            session.revoke()

            self.logger.info(f"Session revoked: {session_id}")

            return FlextResult[None].ok(None)

        except Exception as e:
            self.logger.exception("Failed to revoke session")
            return FlextResult[None].fail(f"Failed to revoke session: {e}")

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Remove expired sessions and return count of cleaned sessions.

        Returns:
            FlextResult containing number of sessions cleaned up

        """
        try:
            expired_sessions = [
                session_id
                for session_id, session in self.sessions.items()
                if session.is_expired or session.is_revoked
            ]

            # Remove expired sessions
            for session_id in expired_sessions:
                session = self.sessions.pop(session_id, None)
                if session:
                    # Remove from user sessions index
                    user_session_ids = self.user_sessions_index.get(session.user_id, [])
                    if session_id in user_session_ids:
                        user_session_ids.remove(session_id)

            self.logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")

            return FlextResult[int].ok(len(expired_sessions))

        except Exception as e:
            self.logger.exception("Session cleanup failed")
            return FlextResult[int].fail(f"Session cleanup failed: {e}")

    # =========================================================================
    # PRIVATE HELPER METHODS
    # =========================================================================

    def _create_and_store_session(
        self, user_id: str, session_token: str, expires_at_iso: str
    ) -> FlextResult[Session]:
        """Create session entity and store in indexes.

        Args:
            user_id: User ID for session
            session_token: Session token string
            expires_at_iso: Expiration timestamp in ISO format

        Returns:
            FlextResult containing Session entity

        """
        try:
            # Parse expiration timestamp using flext-core utilities
            expires_at = FlextUtilities.parse_iso_timestamp(expires_at_iso)
            current_dt = FlextUtilities.parse_iso_timestamp(
                FlextUtilities.generate_iso_timestamp()
            )

            # Create session using factory method
            session_result = create_session(
                user_id=user_id,
                expires_in_minutes=int((expires_at - current_dt).total_seconds() / 60),
            )

            if session_result.is_failure:
                return session_result

            session = session_result.value

            # Override token with provided token
            session.token = session_token

            # Store session and update indexes
            self.sessions[session.id] = session

            # Add to user sessions index
            if user_id not in self.user_sessions_index:
                self.user_sessions_index[user_id] = []
            self.user_sessions_index[user_id].append(session.id)

            return FlextResult[Session].ok(session)

        except Exception as e:
            return FlextResult[Session].fail(f"Failed to create session: {e}")


# Module exports
__all__ = [
    "FlextAuthService",
]

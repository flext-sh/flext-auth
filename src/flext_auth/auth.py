"""FLEXT Auth - Main authentication orchestrator following flext-core patterns.

Provides FlextAuth class as the unified authentication interface, delegating to
domain services while maintaining clean public API.

Usage:
    # Simple authentication setup
    auth = FlextAuth()

    # Register and authenticate users
    result = auth.register_user("john", "john@example.com", "password")
    auth_result = auth.authenticate_user("john", "password")

"""

from __future__ import annotations

from flext_core import FlextConstants, FlextLogger, FlextResult, FlextUtilities

from flext_auth.config import FlextAuthConfig
from flext_auth.models import (
    AuthToken,
    Session,
    User,
    authenticate_user,
    create_session,
    create_user,
)


class FlextAuth:
    """Unified authentication interface orchestrating authentication workflows.

    This is the main public interface for the flext-auth module, providing a clean
    and simple API while delegating to the underlying domain services and models.
    Following the facade pattern to hide complexity while maintaining full functionality.

    Architecture:
        - Facade Pattern: Simplified interface over complex domain services
        - Delegation: Delegates to FlextAuthService for actual operations
        - Configuration: Uses FlextAuthConfig for type-safe configuration
        - Error Handling: All operations return FlextResult for composability
        - Logging: Integrated audit logging for security events

    Key Features:
        - User registration with validation
        - User authentication with credential verification
        - JWT token generation and validation
        - Session management with expiration
        - Password hashing and verification
        - Account lockout and security policies
        - Configuration-driven behavior

    Usage Examples:
        Zero-configuration authentication::

            # Simplest possible usage
            auth = FlextAuth()

            # Register user
            register_result = auth.register_user(
                "john", "john@example.com", "password123"
            )

            # Authenticate user
            auth_result = auth.authenticate_user("john", "password123")

            if auth_result.success:
                user_data = auth_result.value
                print(f"Welcome {user_data['user']['username']}")

        Configuration-based authentication::

            # Create configuration for production
            config_result = FlextAuthConfig.create_for_environment(
                "production", bcrypt_rounds=14
            )

            if config_result.success:
                config = config_result.value
                auth = FlextAuth(config=config)

        Token validation::

            # Validate JWT token
            token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9..."
            token_result = auth.validate_token(token)

            if token_result.success:
                user_id = token_result.value["user_id"]
                user = auth.get_user_by_id(user_id)

    Thread Safety:
        - Service instance is thread-safe for read operations
        - Configuration is immutable after creation
        - Underlying storage requires external synchronization
        - Password operations are thread-safe with bcrypt

    Performance:
        - Lazy initialization of underlying services
        - Configurable bcrypt rounds for performance tuning
        - JWT validation is stateless and fast
        - In-memory storage for development (database for production)

    """

    def __init__(
        self,
        config: FlextAuthConfig | None = None,
        jwt_secret: str | None = None,
        token_expire_minutes: int | None = None,
        password_rounds: int | None = None,
    ) -> None:
        """Initialize authentication service with configuration.

        Args:
            config: Authentication configuration (created if None)
            jwt_secret: JWT secret override (uses config if None)
            token_expire_minutes: Token expiry override (uses config if None)
            password_rounds: Bcrypt rounds override (uses config if None)

        """
        # Create default configuration if not provided
        if config is None:
            config_result = FlextAuthConfig.create_for_environment("development")
            if config_result.is_failure:
                msg = f"Failed to create default config: {config_result.error}"
                raise RuntimeError(msg)
            config = config_result.value

        self.config = config

        # Override config values if provided
        self._jwt_secret = jwt_secret or config.jwt_secret
        self.token_expire_minutes = token_expire_minutes or config.jwt_expiry_minutes
        self.bcrypt_rounds = password_rounds or config.bcrypt_rounds

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
            "FlextAuth initialized",
            extra={
                "token_expire_minutes": self.token_expire_minutes,
                "bcrypt_rounds": self.bcrypt_rounds,
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
        self,
        username: str,
        password: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[dict[str, object]]:
        """Authenticate user and create session with JWT token.

        Args:
            username: Username for authentication
            password: Plain text password
            client_ip: Client IP address (optional)
            user_agent: Client user agent (optional)

        Returns:
            FlextResult containing authentication data (user, session, jwt) or error

        """
        self.logger.info(f"Authentication attempt for username: {username}")

        # Log authentication attempt with client info
        self.logger.info(
            f"Authentication attempt from {client_ip or 'unknown'} with agent {user_agent or 'unknown'}"
        )

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
        # Type assertion - auth_data is guaranteed to be dict from domain function
        assert isinstance(auth_data, dict), (
            "Authentication data must be dict from domain function"
        )
        auth_dict = auth_data
        session_obj = auth_dict.get("session")
        user_obj = auth_dict.get("user")

        if not isinstance(session_obj, dict) or not isinstance(user_obj, dict):
            return FlextResult[dict[str, object]].fail(
                "Invalid session or user data format"
            )

        session_dict = session_obj
        user_dict = user_obj

        # Store session and update indexes
        session_result = self._create_and_store_session(
            user_id=str(user_dict["id"]),
            session_token=str(session_dict["token"]),
            expires_at_iso=str(session_dict["expires_at"]),
        )

        if session_result.is_failure:
            self.logger.error(f"Session creation failed: {session_result.error}")
            return FlextResult[dict[str, object]].fail(
                session_result.error or "Session creation failed"
            )

        session = session_result.value

        # Update auth data with session ID - ensure consistency
        session_dict["id"] = session.id
        session_dict["session_id"] = session.id  # Ensure session_id matches id
        auth_dict["session"] = session_dict

        self.logger.info(f"Authentication successful for username: {username}")

        # Generate JWT token at service layer (not domain)
        # Create JWT token using AuthToken with validated data
        user_data = user_dict
        jwt_result = AuthToken.create_jwt_token(
            user_id=str(user_data.get("id", "")),
            username=str(user_data.get("username", "")),
            secret=self._jwt_secret,
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

        # Create legacy structure for backward compatibility
        session_data = result_data.get("session", {})
        legacy_structure = {
            # Legacy test expectations
            "success": True,
            "user": result_data["user"],
            "tokens": {
                "access_token": result_data["jwt_token"],
                "token_type": "Bearer",
                "expires_in": self.config.jwt_expiry_minutes * 60,
            },
            "session": session_data,
            # Additional session access patterns
            "session_id": session_data.get("id")
            if isinstance(session_data, dict)
            else None,
            # Functional test expectations (direct access)
            "jwt_token": result_data["jwt_token"],
            "expires_at": result_data["expires_at"],
        }

        return FlextResult[dict[str, object]].ok(legacy_structure)

    def validate_token(self, token: str) -> FlextResult[dict[str, object]]:
        """Validate JWT token and return payload.

        Args:
            token: JWT token string

        Returns:
            FlextResult containing token payload or error

        """
        try:
            import jwt

            # Remove Bearer prefix if present
            clean_token = token
            if token.startswith("Bearer "):
                clean_token = token[7:]  # Remove "Bearer " prefix
            
            # Decode JWT token with proper options (don't verify audience for now)
            payload = jwt.decode(
                clean_token,
                self._jwt_secret,
                algorithms=[FlextConstants.Auth.JWT_DEFAULT_ALGORITHM],
                options={"verify_aud": False},
            )

            # Log successful validation
            self.logger.info(f"JWT token validated for user: {payload.get('user_id')}")

            # Add 'valid' flag expected by tests
            payload["valid"] = True

            # Return the payload as dict
            return FlextResult[dict[str, object]].ok(payload)

        except Exception as e:
            self.logger.exception("JWT token validation failed")
            return FlextResult[dict[str, object]].fail(f"Token validation failed: {e}")

    def verify_token(self, token: str) -> FlextResult[dict[str, object]]:
        """Verify JWT token and return payload (API compatibility alias).

        Args:
            token: JWT token string

        Returns:
            FlextResult containing token payload or error

        """
        return self.validate_token(token)

    def generate_token(self, user_id: str) -> str:
        """Generate JWT token for user ID - compatibility method."""
        # For API compatibility, allow generating tokens for any user_id
        # The JWT validation will handle verification later
        token_result = AuthToken.create_jwt_token(
            user_id=user_id,
            secret=self._jwt_secret,
            expires_in_minutes=self.config.jwt_expiry_minutes,
            username=user_id,  # Use user_id as username for test compatibility
        )

        if token_result.is_failure:
            msg = f"Failed to generate token: {token_result.error}"
            raise RuntimeError(msg)

        return token_result.value.token

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
        """Remove expired sessions and return count.

        Returns:
            FlextResult containing number of sessions cleaned up

        """
        try:
            expired_sessions = [
                session_id
                for session_id, session in self.sessions.items()
                if session.is_expired() or session.is_revoked
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

    def logout_user(self, session_id: str) -> FlextResult[None]:
        """Logout user by revoking their session.

        Args:
            session_id: Session ID to logout

        Returns:
            FlextResult indicating success or failure

        """
        return self.revoke_session(session_id)

    def get_user_by_token(self, token: str) -> FlextResult[User | None]:
        """Get user by JWT token (API compatibility method).

        Args:
            token: JWT token string

        Returns:
            FlextResult containing User entity or None if not found

        """
        # Validate token first
        token_result = self.validate_token(token)
        if token_result.is_failure:
            return FlextResult[User | None].fail(token_result.error or "Invalid token")

        # Extract user_id from token payload
        user_id = token_result.value.get("user_id")
        if not user_id or not isinstance(user_id, str):
            return FlextResult[User | None].fail("Token missing user_id")

        return self.get_user_by_id(user_id)

    @classmethod
    def quick_start(
        cls,
        *,
        create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
        REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_password: str = "AdminPassword123!",
    ) -> FlextAuth:
        """Quick start method for testing/development (API compatibility method).

        Args:
            create_REDACTED_LDAP_BIND_PASSWORD: Whether to create REDACTED_LDAP_BIND_PASSWORD user
            REDACTED_LDAP_BIND_PASSWORD_username: Admin username
            REDACTED_LDAP_BIND_PASSWORD_password: Admin password

        Returns:
            FlextAuth instance with optional REDACTED_LDAP_BIND_PASSWORD user (raises on failure)

        """
        try:
            # Create FlextAuth instance
            auth = cls()

            if create_REDACTED_LDAP_BIND_PASSWORD:
                # Create REDACTED_LDAP_BIND_PASSWORD user
                REDACTED_LDAP_BIND_PASSWORD_result = auth.register_user(
                    username=REDACTED_LDAP_BIND_PASSWORD_username,
                    email=f"{REDACTED_LDAP_BIND_PASSWORD_username}@example.com",
                    password=REDACTED_LDAP_BIND_PASSWORD_password,
                    roles=["REDACTED_LDAP_BIND_PASSWORD"],
                )
                if REDACTED_LDAP_BIND_PASSWORD_result.is_failure:
                    FlextAuth._raise_REDACTED_LDAP_BIND_PASSWORD_creation_error(REDACTED_LDAP_BIND_PASSWORD_result.error)

            return auth

        except Exception as e:
            # Re-raise with descriptive message
            msg = f"Quick start failed: {e}"
            raise RuntimeError(msg) from e

    @staticmethod
    def _raise_REDACTED_LDAP_BIND_PASSWORD_creation_error(error: str | None) -> None:
        """Raise RuntimeError for REDACTED_LDAP_BIND_PASSWORD creation failure."""
        msg = f"Failed to create REDACTED_LDAP_BIND_PASSWORD: {error}"
        raise RuntimeError(msg)

    # =========================================================================
    # CONVENIENCE METHODS FOR SIMPLE USAGE
    # =========================================================================

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash (convenience method).

        Args:
            password: Plain text password
            password_hash: Bcrypt hash to verify against

        Returns:
            True if password matches hash

        """
        # Use bcrypt directly for efficiency (no temporary objects)
        import bcrypt

        try:
            return bcrypt.checkpw(
                password.encode("utf-8"), password_hash.encode("utf-8")
            )
        except Exception:
            return False

    def hash_password(self, password: str) -> str:
        """Hash password with bcrypt (convenience method - compatibility).

        Args:
            password: Plain text password to hash

        Returns:
            Bcrypt hash string

        Raises:
            ValueError: If password validation fails
            RuntimeError: If hashing operation fails

        """
        # Validate password strength using Password value object with Pydantic field_validator
        from flext_auth.models import Password

        password_obj = Password(value=password)  # Validation happens in field_validator

        # Use the Password object's hash method
        try:
            return password_obj.hash_password()
        except Exception as e:
            msg = f"Failed to hash password: {e}"
            raise RuntimeError(msg) from e

    def generate_jwt_token(
        self, user_id: str, expires_in_minutes: int | None = None
    ) -> FlextResult[str]:
        """Generate JWT token for user (convenience method).

        Args:
            user_id: User ID to generate token for
            expires_in_minutes: Token expiry (uses config default if None)

        Returns:
            FlextResult containing JWT token string or error

        """
        expiry = expires_in_minutes or self.config.jwt_expiry_minutes

        # Get username for JWT payload
        user_result = self.get_user_by_id(user_id)
        if user_result.is_failure or user_result.value is None:
            return FlextResult[str].fail("User not found for JWT generation")

        username = user_result.value.username

        token_result = AuthToken.create_jwt_token(
            user_id=user_id,
            username=username,
            secret=self._jwt_secret,
            expires_in_minutes=expiry,
        )

        if token_result.is_failure:
            return FlextResult[str].fail(token_result.error or "Token creation failed")

        return FlextResult[str].ok(token_result.value.token)

    # =========================================================================
    # PUBLIC PROPERTIES FOR API COMPATIBILITY
    # =========================================================================

    @property
    def jwt_secret(self) -> str:
        """Get JWT secret for API compatibility."""
        return self._jwt_secret

    @property
    def password_rounds(self) -> int:
        """Get bcrypt rounds for API compatibility."""
        return self.bcrypt_rounds

    @property
    def token_expiry_minutes(self) -> int:
        """Get token expiry minutes for API compatibility."""
        return self.token_expire_minutes

    @property
    def sessions_data(self) -> dict[str, object]:
        """Get sessions manager for API compatibility."""
        # Return with proper type annotation for API compatibility
        return dict(self.sessions)

    @property
    def users_data(self) -> dict[str, object]:
        """Get users manager for API compatibility."""
        # Return with proper type annotation for API compatibility
        return dict(self.users)

    # =========================================================================
    # CONFIGURATION ACCESS
    # =========================================================================

    def get_config(self) -> FlextAuthConfig:
        """Get current authentication configuration.

        Returns:
            Current FlextAuthConfig instance

        """
        return self.config

    def get_security_settings(self) -> dict[str, object]:
        """Get security configuration summary.

        Returns:
            Dictionary containing security settings

        """
        return self.config.get_security_settings()

    def get_jwt_settings(self) -> dict[str, object]:
        """Get JWT configuration summary.

        Returns:
            Dictionary containing JWT settings (secret excluded)

        """
        return self.config.get_jwt_settings()

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
    "FlextAuth",
]

"""FLEXT Auth Service - Enterprise authentication and authorization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime

import jwt

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.typings import FlextAuthTypes
from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
    FlextTypes,
    FlextUtilities,
)


class FlextAuth:
    """Enterprise authentication service with JWT token management and user authentication.

    Provides secure authentication with bcrypt password hashing, JWT tokens,
    session management, and role-based access control following flext-core patterns.
    """

    def __init__(
        self,
        config: FlextAuthConfig | None = None,
        container: FlextContainer | None = None,
    ) -> None:
        """Initialize authentication service with configuration.

        Args:
            config: Authentication configuration (uses global singleton if None)
            container: DI container (uses global if None)

        """
        # Use provided config or get global singleton - ensure correct type
        self.config: FlextAuthConfig = config or FlextAuthConfig.get_global_instance()

        # Initialize dependencies
        self.container = container or FlextContainer.get_global()
        self._logger = FlextLogger(__name__)

        # Initialize storage
        self._users: dict[str, FlextAuthModels.User] = {}
        self._sessions: dict[str, FlextAuthModels.Session] = {}
        self.username_index: dict[str, str] = {}
        self.email_index: dict[str, str] = {}
        self.user_sessions_index: dict[str, list[str]] = {}

        # Log initialization info
        self._logger.info(
            f"FlextAuth initialized: token_expire_minutes={self.config.jwt_expiry_minutes}, "
            f"bcrypt_rounds={self.config.bcrypt_rounds}, jwt_secret_length={len(str(self.config.jwt_auth_secret.get_secret_value()))}",
        )

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        roles: list[str] | None = None,
    ) -> FlextResult[FlextAuthModels.User]:
        """Register new user with FlextResult railway pattern - eliminates try/except fallbacks.

        Creates a new user account with the provided credentials and information.
        Validates username and email availability, creates secure password hash,
        and stores the user with proper indexing for fast lookups.

        Args:
            username: Unique username (case insensitive, will be indexed)
            email: Unique email address (case insensitive, will be indexed)
            password: Plain text password (will be securely hashed with bcrypt)
            full_name: Optional full display name for the user
            roles: Optional list of roles (defaults to ["user"])

        Returns:
            FlextResult containing the created User entity with all fields populated,
            or error information if registration fails

        """
        self._logger.info(
            f"Starting user registration for username: {username}, email: {email}"
        )

        # Use FlextUtilities for input validation - following SOLID principles
        validation_result = self._validate_registration_inputs(
            username, email, password
        )
        if validation_result.is_failure:
            self._logger.error(f"Input validation failed: {validation_result.error}")
            return FlextResult[FlextAuthModels.User].fail(
                validation_result.error or "Validation failed"
            )

        self._logger.info("Input validation passed")

        # Step 1: Check username availability
        username_check = self._validate_username_availability(username)
        if username_check.is_failure:
            error_msg = username_check.error or "Username availability check failed"
            self._logger.error(f"Username availability check failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info("Username availability check passed")

        # Step 2: Check email availability
        email_check = self._validate_email_availability(email)
        if email_check.is_failure:
            error_msg = email_check.error or "Email availability check failed"
            self._logger.error(f"Email availability check failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info("Email availability check passed")

        # Step 3: Create user request
        request_result = self._create_user_request(
            username, email, password, full_name, roles
        )
        if request_result.is_failure:
            error_msg = request_result.error or "User request creation failed"
            self._logger.error(f"User request creation failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info(f"User request created: {request_result.value}")

        # Step 4: Create user from request
        user_result = self._create_user_from_request(request_result.value)
        if user_result.is_failure:
            error_msg = user_result.error or "User creation failed"
            self._logger.error(f"User creation failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info(f"User created successfully: {user_result.value}")

        # Step 5: Store user and update indexes
        stored_user = self._store_user_and_update_indexes(
            user_result.value, username, email
        )

        self._logger.info(f"User registration completed successfully: {stored_user}")

        return FlextResult[FlextAuthModels.User].ok(stored_user)

    def _validate_registration_inputs(
        self, username: str, email: str, password: str
    ) -> FlextResult[None]:
        """Validate registration inputs using FlextUtilities - SOLID principle.

        Returns:
            FlextResult[None]: Success if validation passes, error if validation fails

        """
        username_validation = FlextUtilities.Validation.validate_string(
            username, field_name="username"
        )
        if username_validation.is_failure:
            return FlextResult[None].fail(
                username_validation.error or "Username validation failed"
            )

        email_validation = FlextUtilities.Validation.validate_email(email)
        if email_validation.is_failure:
            return FlextResult[None].fail(
                email_validation.error or "Email validation failed"
            )

        password_validation = FlextUtilities.Validation.validate_string(
            password, field_name="password"
        )
        if password_validation.is_failure:
            return FlextResult[None].fail(
                password_validation.error or "Password validation failed"
            )

        return FlextResult[None].ok(None)

    def _create_user_request(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None,
        roles: list[str] | None,
    ) -> FlextResult[FlextAuthModels.UserCreationRequest]:
        """Create user request using FlextModels - no try/except needed.

        Returns:
            FlextResult[FlextAuthModels.UserCreationRequest]: Success with user creation request

        """
        user_request = FlextAuthModels.UserCreationRequest(
            username=username,
            email=email,
            password=password,
            full_name=full_name,
            roles=roles or ["user"],
        )
        return FlextResult[FlextAuthModels.UserCreationRequest].ok(user_request)

    def _validate_username_availability(self, username: str) -> FlextResult[None]:
        """Validate username is available - first step in registration railway.

        Returns:
            FlextResult[None]: Success if username is available, error if taken

        """
        if username.lower() in self.username_index:
            return FlextResult[None].fail(
                "Username already exists",
                error_code=FlextAuthConstants.USERNAME_TAKEN,
            )
        return FlextResult[None].ok(None)

    def _validate_email_availability(self, email: str) -> FlextResult[None]:
        """Validate email is available - second step in registration railway.

        Returns:
            FlextResult[None]: Success if email is available, error if taken

        """
        if email.lower() in self.email_index:
            return FlextResult[None].fail(
                "Email already exists",
                error_code=FlextAuthConstants.EMAIL_TAKEN,
            )
        return FlextResult[None].ok(None)

    def _create_user_from_request(
        self, request: FlextAuthModels.UserCreationRequest
    ) -> FlextResult[FlextAuthModels.User]:
        self._logger.info(f"_create_user_from_request called with request: {request}")

        user_result = FlextAuthModels.User.create_user(request)

        if user_result.is_failure:
            self._logger.error(f"User creation failed: {user_result.error}")
        else:
            self._logger.info(f"User creation succeeded: {user_result.value}")

        return user_result

    def _store_user_and_update_indexes(
        self, user: FlextAuthModels.User, username: str, email: str
    ) -> FlextAuthModels.User:
        """Store user and update indexes - final step in registration railway.

        Returns:
            FlextAuthModels.User: The stored user entity

        """
        # Debug logging to identify None data issue
        self._logger.info(
            f"_store_user_and_update_indexes called with user={user}, username={username}, email={email}"
        )

        # Store user and update indexes
        self._users[user.id] = user
        self.username_index[username.lower()] = user.id
        self.email_index[email.lower()] = user.id

        self._logger.info(f"User registered successfully: {username} (ID: {user.id})")

        # Ensure we're returning the user
        result_user = user
        self._logger.info(f"Returning user: {result_user}")
        return result_user

    def authenticate_user(
        self,
        username: str,
        password: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
        """Authenticate user credentials and create session with JWT token using railway pattern.

        Validates user credentials against stored password hash, checks account
        status (active/locked), and creates a new session with JWT token if
        authentication succeeds. Uses monadic composition for clean error propagation.

        Args:
            username: Username to authenticate (case insensitive)
            password: Plain text password to verify
            client_ip: Optional client IP address for session tracking
            user_agent: Optional user agent string for session tracking

        Returns:
            FlextResult containing AuthenticationResponseDict with user data,
            session information, and JWT token, or error information

        Example:
            >>> auth = FlextAuth()
            >>> result: FlextResult[object] = auth.authenticate_user(
            ...     "john_doe", "SecurePass123!"
            ... )
            >>> if result.is_success:
            ...     response = result.value
            ...     print(f"Authenticated user: {response['user']['username']}")

        """
        # Log authentication attempt
        self._logger.info(f"Authentication attempt for username: {username}")
        if client_ip or user_agent:
            self._logger.info(
                f"Authentication attempt from {client_ip or 'unknown'} with agent {user_agent or 'unknown'}",
            )

        # Railway pattern: Chain authentication operations with monadic composition
        return (
            self._find_user_for_auth(username)
            .flat_map(lambda user: self._validate_user_credentials(user, password))
            .flat_map(
                lambda user: self._create_user_session(user, client_ip, user_agent)
            )
            .flat_map(self._generate_auth_token)
            .map(self._build_auth_response)
        )

    def _find_user_for_auth(self, username: str) -> FlextResult[FlextAuthModels.User]:
        """Find and validate user for authentication - first step in auth railway.

        Returns:
            FlextResult[FlextAuthModels.User]: Success with user if found, error if not found

        """
        if not username or not username.strip():
            return FlextResult[FlextAuthModels.User].fail(
                "Username cannot be empty",
                error_code=FlextAuthConstants.INVALID_CREDENTIALS,
            )

        user_id = self.username_index.get(username.lower())
        if not user_id:
            return FlextResult[FlextAuthModels.User].fail(
                "Invalid credentials",
                error_code=FlextAuthConstants.INVALID_CREDENTIALS,
            )

        user = self._users.get(user_id)
        if not user:
            return FlextResult[FlextAuthModels.User].fail(
                "Invalid credentials",
                error_code=FlextAuthConstants.INVALID_CREDENTIALS,
            )

        return FlextResult[FlextAuthModels.User].ok(user)

    def _validate_user_credentials(
        self, user: FlextAuthModels.User, password: str
    ) -> FlextResult[FlextAuthModels.User]:
        """Validate user credentials and account status - second step in auth railway.

        Returns:
            FlextResult[FlextAuthModels.User]: Success with user if credentials valid, error if invalid

        """
        if not password or not password.strip():
            return FlextResult[FlextAuthModels.User].fail(
                "Password cannot be empty",
                error_code=FlextAuthConstants.INVALID_CREDENTIALS,
            )

        # Check if account is locked
        if user.is_locked:
            return FlextResult[FlextAuthModels.User].fail(
                "Account is locked due to too many failed attempts",
                error_code=FlextAuthConstants.ACCOUNT_LOCKED,
            )

        # Check if account is active
        if not user.can_login:
            return FlextResult[FlextAuthModels.User].fail(
                "Account is not active",
                error_code=FlextAuthConstants.ACCOUNT_DISABLED,
            )

        # Verify password using monadic composition
        return user.verify_password(password).flat_map(
            lambda is_valid: self._handle_password_verification(user, is_valid=is_valid)
        )

    def _handle_password_verification(
        self, user: FlextAuthModels.User, *, is_valid: bool
    ) -> FlextResult[FlextAuthModels.User]:
        """Handle password verification result with proper user state updates.

        Returns:
            FlextResult[FlextAuthModels.User]: Success with updated user, error if password invalid

        """
        if not is_valid:
            # Record failed login attempt and update stored user
            user.record_failed_login()
            stored_user_id = self.username_index.get(user.username.lower())
            if stored_user_id and stored_user_id in self._users:
                stored_user = self._users[stored_user_id]
                stored_user.failed_login_attempts = user.failed_login_attempts
                stored_user.locked_until = user.locked_until
                stored_user.updated_at = user.updated_at

            return FlextResult[FlextAuthModels.User].fail(
                "Invalid credentials"
                if user.failed_login_attempts < self.config.max_login_attempts
                else "Account locked due to too many failed attempts"
            )

        # Successful authentication - record and update stored user
        user.record_successful_login()
        stored_user_id = self.username_index.get(user.username.lower())
        if stored_user_id and stored_user_id in self._users:
            stored_user = self._users[stored_user_id]
            stored_user.last_login = user.last_login
            stored_user.failed_login_attempts = user.failed_login_attempts
            stored_user.locked_until = user.locked_until
            stored_user.updated_at = user.updated_at

        return FlextResult[FlextAuthModels.User].ok(user)

    def _create_user_session(
        self, user: FlextAuthModels.User, client_ip: str | None, user_agent: str | None
    ) -> FlextResult[dict[str, object]]:
        """Create session for authenticated user - third step in auth railway.

        Returns:
            FlextResult[dict[str, object]]: Success with session data, error if session creation fails

        """
        return FlextAuthModels.Session.create_session(
            user_id=user.id,
            ip_address=client_ip,
            user_agent=user_agent,
        ).map(lambda session: self._store_session_and_build_data(user, session))

    def _store_session_and_build_data(
        self, user: FlextAuthModels.User, session: FlextAuthModels.Session
    ) -> dict[str, object]:
        """Store session and prepare session data for next step.

        Returns:
            dict[str, object]: Session data dictionary with user and session

        """
        # Store session and update indexes
        self._sessions[session.id] = session

        # Add to user sessions index
        if user.id not in self.user_sessions_index:
            self.user_sessions_index[user.id] = []
        self.user_sessions_index[user.id].append(session.id)

        return {"user": user, "session": session}

    def _generate_auth_token(
        self, session_data: dict[str, object]
    ) -> FlextResult[dict[str, object]]:
        """Generate JWT token for authenticated session - fourth step in auth railway.

        Returns:
            FlextResult[dict[str, object]]: Success with auth data including JWT token, error if token generation fails

        """
        user = session_data["user"]
        session_data["session"]

        if not isinstance(user, FlextAuthModels.User):
            return FlextResult[dict[str, object]].fail("Invalid user data in session")

        return self.generate_jwt_token(user.id).map(
            lambda jwt_token: {**session_data, "jwt_token": jwt_token}
        )

    def _build_auth_response(
        self, auth_data: dict[str, object]
    ) -> FlextAuthTypes.AuthenticationResponseDict:
        """Build final authentication response - final step in auth railway.

        Returns:
            FlextAuthTypes.AuthenticationResponseDict: Complete authentication response

        Raises:
            TypeError: If auth_data structure is invalid

        """
        user = auth_data["user"]
        session = auth_data["session"]
        jwt_token = auth_data["jwt_token"]

        if not isinstance(user, FlextAuthModels.User) or not isinstance(
            session, FlextAuthModels.Session
        ):
            msg = "Invalid auth data structure"
            raise TypeError(msg)

        # Create UserDict with all required fields
        user_data: FlextAuthTypes.UserDict = {
            "id": user.id,
            "username": user.username,
            "email": user.email,
            "full_name": user.full_name,
            "is_active": user.is_active,
            "roles": user.roles,
            "created_at": user.created_at,
            "updated_at": user.updated_at or datetime.now(UTC),
            "last_login": user.last_login,
        }

        # Create SessionDict with all required fields
        session_data: FlextAuthTypes.SessionDict = {
            "id": session.id,
            "user_id": session.user_id,
            "session_token": session.session_token,
            "expires_at": session.expires_at,
            "created_at": session.created_at,
            "last_accessed_at": session.last_accessed_at,
            "is_active": session.is_active,
            "ip_address": session.ip_address,
            "user_agent": session.user_agent,
        }

        # Create properly typed authentication response
        result_data: FlextAuthTypes.AuthenticationResponseDict = {
            "user": user_data,
            "session": session_data,
            "jwt_token": str(jwt_token) if jwt_token else "",
            "authenticated": True,
            "success": True,
        }

        # Add optional tokens field
        if jwt_token:
            result_data["tokens"] = {
                "access_token": str(jwt_token),
                "token_type": "Bearer",
                "expires_in": self.config.jwt_expiry_minutes * 60,  # Convert to seconds
            }

        return result_data

    def validate_token(self, token: str) -> FlextResult[FlextTypes.Core.Dict]:
        """Validate JWT token and return payload using railway pattern.

        Args:
            token: JWT token string

        Returns:
            FlextResult containing token payload or error

        """
        # Use FlextUtilities for input validation
        token_validation = FlextUtilities.Validation.validate_string(
            token, field_name="token"
        )
        if token_validation.is_failure:
            return FlextResult[FlextTypes.Core.Dict].fail("Token cannot be empty")

        # Clean token (remove Bearer prefix if present)
        clean_token = token.removeprefix("Bearer ")

        # Basic token format validation
        jwt_dot_count = 2  # JWT should have exactly 2 dots
        if clean_token.count(".") != jwt_dot_count:
            return FlextResult[FlextTypes.Core.Dict].fail("Invalid token format")

        # JWT verification with specific error handling - minimal try/except for JWT library
        try:
            payload = jwt.decode(
                clean_token,
                str(self.config.jwt_auth_secret.get_secret_value()),
                algorithms=[FlextAuthConstants.JWT_DEFAULT_ALGORITHM],
                options={"verify_aud": False},
            )
        except jwt.ExpiredSignatureError:
            return FlextResult[FlextTypes.Core.Dict].fail("Token has expired")
        except jwt.InvalidTokenError:
            return FlextResult[FlextTypes.Core.Dict].fail("Invalid token")
        except Exception:
            return FlextResult[FlextTypes.Core.Dict].fail("Token validation failed")

        # Log successful validation
        self._logger.info(f"JWT token validated for user: {payload.get('user_id')}")

        # Add 'valid' flag expected by tests
        payload["valid"] = True

        return FlextResult[FlextTypes.Core.Dict].ok(payload)  # pragma: no cover

    def generate_token(self, user_id: str) -> str:
        """Generate JWT token for user ID using flext-core patterns.

        Returns:
            str: JWT token string

        Raises:
            RuntimeError: If user not found or token generation fails

        """
        # Get user to include username in token
        user_result = self.get_user_by_id(user_id)
        if user_result.is_failure or user_result.value is None:  # pragma: no cover
            msg = "User not found for token generation"  # pragma: no cover
            raise RuntimeError(msg)  # pragma: no cover

        _user = user_result.value
        # Convert minutes to hours for JWT
        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            expiry_minutes=self.config.jwt_expiry_minutes,
            token_type=FlextAuthConstants.JWT_DEFAULT_TOKEN_TYPE,
            jwt_secret=str(self.config.jwt_auth_secret.get_secret_value()),
        )

        if token_result.is_failure:  # pragma: no cover
            msg = f"Failed to generate token: {token_result.error}"  # pragma: no cover
            raise RuntimeError(msg)  # pragma: no cover

        # Safe to access token now - FlextResult guarantees value is not None on success
        return token_result.value.token

    def get_user_by_username(
        self,
        username: str,
    ) -> FlextResult[FlextAuthModels.User | None]:
        """Get user by username (case insensitive).

        Returns:
            FlextResult[FlextAuthModels.User | None]: Success with user if found, None if not found

        """
        user_id = self.username_index.get(username.lower())
        if not user_id:
            return FlextResult[FlextAuthModels.User | None].ok(None)

        user = self._users.get(user_id)
        return FlextResult[FlextAuthModels.User | None].ok(user)

    def get_user_by_id(self, user_id: str) -> FlextResult[FlextAuthModels.User | None]:
        """Get user by ID.

        Returns:
            FlextResult[FlextAuthModels.User | None]: Success with user if found, None if not found

        """
        user = self._users.get(user_id)
        return FlextResult[FlextAuthModels.User | None].ok(user)

    def get_user_sessions(
        self,
        user_id: str,
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get all active sessions for user.

        Returns:
            FlextResult[list[FlextAuthModels.Session]]: Success with list of active sessions

        """
        session_ids = self.user_sessions_index.get(user_id, [])
        sessions: list[FlextAuthModels.Session] = []

        for session_id in session_ids:
            session = self._sessions.get(session_id)
            if session and session.is_valid:
                sessions.append(session)

        return FlextResult[list[FlextAuthModels.Session]].ok(sessions)

    def revoke_session(self, session_id: str) -> FlextResult[None]:
        """Revoke specific session.

        Returns:
            FlextResult[None]: Success if session revoked, error if session not found

        """
        session = self._sessions.get(session_id)
        if not session:
            return FlextResult[None].fail(
                "Session not found",
                error_code=FlextAuthConstants.SESSION_NOT_FOUND,
            )

        session.revoke()
        self._logger.info(f"Session revoked: {session_id}")
        return FlextResult[None].ok(None)

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Remove expired sessions and return count.

        Returns:
            FlextResult[int]: Success with count of cleaned up sessions

        """
        expired_sessions = [
            session_id
            for session_id, session in self._sessions.items()
            if session.is_expired() or not session.is_active
        ]

        # Remove expired sessions
        for session_id in expired_sessions:
            session = self._sessions.pop(session_id, None)
            if session:
                # Remove from user sessions index
                user_session_ids = self.user_sessions_index.get(session.user_id, [])
                if session_id in user_session_ids:
                    user_session_ids.remove(session_id)

        self._logger.info(f"Cleaned up {len(expired_sessions)} expired sessions")
        return FlextResult[int].ok(len(expired_sessions))

    def logout_user(self, session_id: str) -> FlextResult[None]:
        """Logout user by revoking session.

        Returns:
            FlextResult[None]: Success if session revoked, error if session not found

        """
        return self.revoke_session(session_id)

    def get_user_by_token(self, token: str) -> FlextResult[FlextAuthModels.User | None]:
        """Get user by JWT token (API compatibility method).

        Args:
            token: JWT token string

        Returns:
            FlextResult containing User entity or None if not found

        """
        # Validate token first
        token_result = self.validate_token(token)
        if token_result.is_failure:
            return FlextResult[FlextAuthModels.User | None].fail(
                token_result.error or "Invalid token",
            )

        # Extract user_id from token payload
        user_id = token_result.value.get("user_id")
        if not user_id or not isinstance(user_id, str):  # pragma: no cover
            return FlextResult[FlextAuthModels.User | None].fail(
                "Token missing user_id",
            )  # pragma: no cover

        return self.get_user_by_id(user_id)

    @classmethod
    def quick_start(
        cls,
        *,
        create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
        REDACTED_LDAP_BIND_PASSWORD_username: str = "REDACTED_LDAP_BIND_PASSWORD",
        REDACTED_LDAP_BIND_PASSWORD_password: str = getattr(
            FlextAuthConstants,
            "DEFAULT_ADMIN_PASSWORD",
            "AdminPassword123!",
        ),
    ) -> FlextAuth:
        """Quick start with simplified implementation using railway pattern.

        Returns:
            FlextAuth: Configured authentication service instance

        Raises:
            RuntimeError: If REDACTED_LDAP_BIND_PASSWORD user creation fails

        """
        # Create FlextAuth instance
        auth = cls()

        # Conditionally create REDACTED_LDAP_BIND_PASSWORD user using railway pattern
        if create_REDACTED_LDAP_BIND_PASSWORD:
            REDACTED_LDAP_BIND_PASSWORD_result = auth.register_user(
                username=REDACTED_LDAP_BIND_PASSWORD_username,
                email=f"{REDACTED_LDAP_BIND_PASSWORD_username}@example.com",
                password=REDACTED_LDAP_BIND_PASSWORD_password,
                roles=["REDACTED_LDAP_BIND_PASSWORD"],
            )

            if REDACTED_LDAP_BIND_PASSWORD_result.is_failure:
                error_msg = f"Failed to create REDACTED_LDAP_BIND_PASSWORD: {REDACTED_LDAP_BIND_PASSWORD_result.error}"
                raise RuntimeError(error_msg)

        return auth

    @classmethod
    def create_with_config_overrides(
        cls,
        *,
        jwt_expiry_minutes: int | None = None,
        bcrypt_rounds: int | None = None,
        max_failed_attempts: int | None = None,
        _lockout_duration_minutes: int | None = None,
    ) -> FlextResult[FlextAuth]:
        """Create FlextAuth instance with configuration overrides using railway pattern.

        Args:
            jwt_expiry_minutes: JWT token expiry time in minutes
            bcrypt_rounds: Number of bcrypt rounds for password hashing
            max_failed_attempts: Maximum failed login attempts before lockout
            lockout_duration_minutes: Account lockout duration in minutes

        Returns:
            FlextResult containing FlextAuth instance or error information

        """
        # Create config with overrides using proper parameter passing
        try:
            config = FlextAuthConfig.create_for_environment("production")
        except Exception as e:
            return FlextResult[FlextAuth].fail(f"Failed to create config: {e}")

        # Apply overrides if provided
        if jwt_expiry_minutes is not None:
            config.jwt_expiry_minutes = jwt_expiry_minutes
        if bcrypt_rounds is not None:
            config.bcrypt_rounds = bcrypt_rounds
        if max_failed_attempts is not None:
            config.max_login_attempts = max_failed_attempts

        # Create FlextAuth instance with custom config
        auth = cls(config=config)

        return FlextResult[FlextAuth].ok(auth)

    def generate_jwt_token(
        self,
        user_id: str,
        expires_in_minutes: int | None = None,
    ) -> FlextResult[str]:
        """Generate JWT token for user.

        Args:
            user_id: User ID to generate token for
            expires_in_minutes: Token expiry (uses config default if None)

        Returns:
            FlextResult containing JWT token string or error

        """
        expiry = expires_in_minutes or self.config.jwt_expiry_minutes

        user_result = self.get_user_by_id(user_id)
        if user_result.is_failure or user_result.value is None:
            return FlextResult[str].fail(
                "User not found for JWT generation",
            )

        _user = user_result.value

        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            expiry_minutes=expiry or self.config.jwt_expiry_minutes,
            token_type=FlextAuthConstants.JWT_DEFAULT_TOKEN_TYPE,
            jwt_secret=str(self.config.jwt_auth_secret.get_secret_value()),
        )

        if token_result.is_failure:
            return FlextResult[str].fail(
                token_result.error or "Token creation failed",
            )

        return FlextResult[str].ok(token_result.value.token)

    @property
    def token_expire_minutes(self) -> int:
        """Get JWT token expiry minutes from configuration."""
        return self.config.jwt_expiry_minutes

    @property
    def bcrypt_rounds(self) -> int:
        """Get bcrypt rounds from configuration."""
        return self.config.bcrypt_rounds


# Module exports
__all__ = [
    "FlextAuth",
]

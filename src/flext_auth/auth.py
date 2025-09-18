"""FLEXT Auth Service - Enterprise authentication and authorization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import jwt

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.container import FlextAuthContainer
from flext_auth.models import FlextAuthModels
from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
    FlextTypes,
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
        # Use provided config or get global singleton
        self.config = config or FlextAuthConfig.get_global_instance()

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
            f"bcrypt_rounds={self.config.bcrypt_rounds}, jwt_secret_length={len(self.config.jwt_secret)}"
        )

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        roles: list[str] | None = None,
    ) -> FlextResult[FlextAuthModels.User]:
        """Register a new user with secure password hashing and validation.

        Creates a new user account with bcrypt password hashing, email validation,
        and role assignment. Checks for duplicate usernames and emails before
        creating the account.

        Args:
            username: Unique username (minimum 3 characters, alphanumeric + underscore)
            email: Valid email address for the user
            password: Plain text password (will be hashed with bcrypt)
            full_name: Optional full name for the user
            roles: Optional list of roles (defaults to ["user"])

        Returns:
            FlextResult containing the created User entity or error information

        Raises:
            ValueError: If username or email validation fails
            RuntimeError: If password hashing fails

        Example:
            >>> auth = FlextAuth()
            >>> result = auth.register_user(
            ...     "john_doe", "john@example.com", "SecurePass123!"
            ... )
            >>> assert result.is_success

        """
        # Check for duplicates first
        if username.lower() in self.username_index:
            return FlextResult[FlextAuthModels.User].fail(
                "Username already exists",
                error_code=FlextAuthConstants.USERNAME_TAKEN,
            )

        if email.lower() in self.email_index:
            return FlextResult[FlextAuthModels.User].fail(
                "Email already exists", error_code=FlextAuthConstants.EMAIL_TAKEN
            )

        request = FlextAuthModels.UserCreationRequest(
            username=username,
            email=email,
            password=password,
            full_name=full_name,
            roles=roles or ["user"],
        )
        user_result = FlextAuthContainer.create_user_from_request(request)

        if user_result.is_failure:
            self._logger.error(f"User creation failed: {user_result.error}")
            return user_result

        user = user_result.value

        # Store user and update indexes
        self._users[user.id] = user
        self.username_index[username.lower()] = user.id
        self.email_index[email.lower()] = user.id

        self._logger.info(f"User registered successfully: {username} (ID: {user.id})")
        return FlextResult[FlextAuthModels.User].ok(user)

    def authenticate_user(
        self,
        username: str,
        password: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextAuthModels.AuthenticationResponseDict]:
        """Authenticate user credentials and create session with JWT token.

        Validates user credentials against stored password hash, checks account
        status (active/locked), and creates a new session with JWT token if
        authentication succeeds. Tracks failed login attempts and applies
        account lockout after maximum attempts.

        Args:
            username: Username to authenticate (case insensitive)
            password: Plain text password to verify
            client_ip: Optional client IP address for session tracking
            user_agent: Optional user agent string for session tracking

        Returns:
            FlextResult containing AuthenticationResponseDict with user data,
            session information, and JWT token, or error information

        Raises:
            ValueError: If credentials are invalid or account is locked
            RuntimeError: If session creation or token generation fails

        Example:
            >>> auth = FlextAuth()
            >>> result = auth.authenticate_user("john_doe", "SecurePass123!")
            >>> if result.is_success:
            ...     response = result.value
            ...     print(f"Authenticated user: {response['user']['username']}")

        """
        # Log authentication attempt
        self._logger.info(f"Authentication attempt for username: {username}")
        if client_ip or user_agent:
            self._logger.info(
                f"Authentication attempt from {client_ip or 'unknown'} with agent {user_agent or 'unknown'}"
            )

        # Use domain function from models.py - no duplication
        # Convert users dict to list format expected by authenticate_user
        users_data: list[dict[str, object]] = [
            user.__dict__
            if hasattr(user, "__dict__")
            else dict(user)
            if hasattr(user, "__iter__")
            else {"username": str(user)}
            for user in self._users.values()
        ]
        # Authenticate user using internal method (moved from _AuthenticationService)
        auth_result = self._authenticate_user_internal(username, password, users_data)

        # Update stored user with lockout state changes (for both success and failure)
        if auth_result.is_success and auth_result.value is not None:
            # Update the stored user with new lockout state
            authenticated_user = auth_result.value
            stored_user_id = self.username_index.get(username.lower())
            if stored_user_id and stored_user_id in self._users:
                stored_user = self._users[stored_user_id]
                # Copy lockout-related fields from authenticated user
                stored_user.failed_login_attempts = (
                    authenticated_user.failed_login_attempts
                )
                stored_user.locked_until = authenticated_user.locked_until
                stored_user.last_login = authenticated_user.last_login
                stored_user.updated_at = authenticated_user.updated_at
        else:
            # Even on failure, we need to update the stored user's failed attempts
            stored_user_id = self.username_index.get(username.lower())
            if stored_user_id and stored_user_id in self._users:
                # Directly update the stored user's failed attempts
                stored_user = self._users[stored_user_id]
                stored_user.record_failed_login()

        # If authentication successful, create proper response data
        if auth_result.is_success and auth_result.value is not None:
            user = auth_result.value

            # Create UserDict with all required fields
            user_data: FlextAuthModels.UserDict = {
                "id": user.id,
                "username": user.username,
                "email": user.email,
                "full_name": user.full_name,
                "is_active": user.is_active,
                "roles": user.roles,
                "created_at": user.created_at,
                "updated_at": user.updated_at,
                "last_login": user.last_login,
            }

            # Create session using factory method
            session_result = FlextAuthContainer.create_session(
                user_id=user.id,
                ip_address=client_ip,
                user_agent=user_agent,
            )

            if session_result.is_success:
                session = session_result.value

                # Store session and update indexes
                self._sessions[session.id] = session

                # Add to user sessions index
                if user.id not in self.user_sessions_index:
                    self.user_sessions_index[user.id] = []
                self.user_sessions_index[user.id].append(session.id)

                # Generate JWT token for the user
                token_result = self.generate_jwt_token(user.id)
                jwt_token = token_result.value if token_result.is_success else ""

                # Create SessionDict with all required fields
                session_data: FlextAuthModels.SessionDict = {
                    "id": session.id,
                    "session_id": session.id,  # Alias for API compatibility
                    "user_id": session.user_id,
                    "session_token": session.session_token,
                    "expires_at": session.expires_at,
                    "created_at": session.created_at,
                    "last_accessed_at": session.last_accessed_at,
                    "is_active": not session.is_revoked,
                    "ip_address": session.ip_address,
                    "user_agent": session.user_agent,
                }

                # Create properly typed authentication response
                result_data: FlextAuthModels.AuthenticationResponseDict = {
                    "user": user_data,
                    "session": session_data,
                    "jwt_token": jwt_token,
                    "authenticated": True,
                    "success": True,
                }

                # Add optional tokens field
                if jwt_token:
                    result_data["tokens"] = {
                        "access_token": jwt_token,
                        "token_type": "Bearer",
                        "expires_in": self.config.jwt_expiry_minutes
                        * 60,  # Convert to seconds
                    }

                return FlextResult[FlextAuthModels.AuthenticationResponseDict].ok(
                    result_data
                )
            return FlextResult[FlextAuthModels.AuthenticationResponseDict].fail(
                f"Session creation failed: {session_result.error}"
            )

        # Return failure if authentication failed
        return FlextResult[FlextAuthModels.AuthenticationResponseDict].fail(
            auth_result.error or "Authentication failed"
        )

    def validate_token(self, token: str) -> FlextResult[FlextTypes.Core.Dict]:
        """Validate JWT token and return payload.

        Args:
            token: JWT token string

        Returns:
            FlextResult containing token payload or error

        """
        try:
            # Remove Bearer prefix if present
            clean_token = token
            if token.startswith("Bearer "):
                clean_token = token[7:]  # Remove "Bearer " prefix

            # Decode JWT token with proper options (don't verify audience for now)
            payload = jwt.decode(
                clean_token,
                self.config.jwt_secret,
                algorithms=[FlextAuthConstants.JWT_DEFAULT_ALGORITHM],
                options={"verify_aud": False},
            )

            # Log successful validation
            self._logger.info(f"JWT token validated for user: {payload.get('user_id')}")

            # Add 'valid' flag expected by tests
            payload["valid"] = True

            # Return the payload as dict
            return FlextResult[FlextTypes.Core.Dict].ok(payload)

        except Exception as e:  # pragma: no cover
            self._logger.exception("JWT token validation failed")  # pragma: no cover
            return FlextResult[FlextTypes.Core.Dict].fail(
                f"Token validation failed: {e}"
            )  # pragma: no cover

    def generate_token(self, user_id: str) -> str:
        """Generate JWT token for user ID using flext-core patterns."""
        # Get user to include username in token
        user_result = self.get_user_by_id(user_id)
        if user_result.is_failure or user_result.value is None:  # pragma: no cover
            msg = "User not found for token generation"  # pragma: no cover
            raise RuntimeError(msg)  # pragma: no cover

        user = user_result.value
        # Convert minutes to hours for JWT
        expires_hours = max(1, self.config.jwt_expiry_minutes // 60)

        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            secret_key=self.config.jwt_secret,
            expires_hours=expires_hours,
            username=user.username,
        )

        if token_result.is_failure:  # pragma: no cover
            msg = f"Failed to generate token: {token_result.error}"  # pragma: no cover
            raise RuntimeError(msg)  # pragma: no cover

        # Safe to access token now - FlextResult guarantees value is not None on success
        return token_result.value.token

    def get_user_by_username(
        self, username: str
    ) -> FlextResult[FlextAuthModels.User | None]:
        """Get user by username (case insensitive)."""
        user_id = self.username_index.get(username.lower())
        if not user_id:
            return FlextResult[FlextAuthModels.User | None].ok(None)

        user = self._users.get(user_id)
        return FlextResult[FlextAuthModels.User | None].ok(user)

    def get_user_by_id(self, user_id: str) -> FlextResult[FlextAuthModels.User | None]:
        """Get user by ID."""
        user = self._users.get(user_id)
        return FlextResult[FlextAuthModels.User | None].ok(user)

    def get_user_sessions(
        self, user_id: str
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get all active sessions for user."""
        session_ids = self.user_sessions_index.get(user_id, [])
        sessions = []

        for session_id in session_ids:
            session = self._sessions.get(session_id)
            if session and session.is_valid:
                sessions.append(session)

        return FlextResult[list[FlextAuthModels.Session]].ok(sessions)

    def revoke_session(self, session_id: str) -> FlextResult[None]:
        """Revoke specific session."""
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
        """Remove expired sessions and return count."""
        expired_sessions = [
            session_id
            for session_id, session in self._sessions.items()
            if session.is_expired() or session.is_revoked
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
        """Logout user by revoking session."""
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
                token_result.error or "Invalid token"
            )

        # Extract user_id from token payload
        user_id = token_result.value.get("user_id")
        if not user_id or not isinstance(user_id, str):  # pragma: no cover
            return FlextResult[FlextAuthModels.User | None].fail(
                "Token missing user_id"
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
        """Quick start with simplified implementation."""
        try:
            # Create FlextAuth instance
            auth = cls()

            # Conditionally create REDACTED_LDAP_BIND_PASSWORD user
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
        except Exception as e:
            error_msg = f"Quick start failed: {e}"
            raise RuntimeError(error_msg) from e

    def generate_jwt_token(
        self, user_id: str, expires_in_minutes: int | None = None
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
        if user_result.is_failure or user_result.value is None:  # pragma: no cover
            return FlextResult[str].fail(
                "User not found for JWT generation"
            )  # pragma: no cover

        user = user_result.value
        # Convert minutes to hours for JWT
        expires_hours = max(1, expiry // 60) if expiry else 1

        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            secret_key=self.config.jwt_secret,
            expires_hours=expires_hours,
            username=user.username,
            roles=user.roles,
        )

        if token_result.is_failure:  # pragma: no cover
            return FlextResult[str].fail(
                token_result.error or "Token creation failed"
            )  # pragma: no cover

        return FlextResult[str].ok(token_result.value.token)

    def _authenticate_user_internal(
        self, username: str, password: str, users_data: list[dict[str, object]]
    ) -> FlextResult[FlextAuthModels.User]:
        """Authenticate user internally."""
        if not username or not password:
            return FlextResult[FlextAuthModels.User].fail(
                "Username and password required"
            )

        # Find user in data (case-insensitive username comparison)
        user_data = next(
            (
                u
                for u in users_data
                if str(u.get("username", "")).lower() == username.lower()
            ),
            None,
        )
        if not user_data:
            return FlextResult[FlextAuthModels.User].fail(
                "Invalid credentials",
                error_code=FlextAuthConstants.INVALID_CREDENTIALS,
            )

        # Create user instance from user data
        user = FlextAuthModels.User()
        # Set user attributes from user_data, but only if they exist in User model
        for key, value in user_data.items():
            if hasattr(user, key):
                setattr(user, key, value)

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

        # Verify password
        password_result = user.verify_password(password)
        if password_result.is_failure or not password_result.data:
            # Record failed login attempt
            user.record_failed_login()
            return FlextResult[FlextAuthModels.User].fail(
                "Invalid credentials",
                error_code=FlextAuthConstants.INVALID_CREDENTIALS,
            )

        # Password verification successful - record successful login
        user.record_successful_login()
        return FlextResult[FlextAuthModels.User].ok(user)


# Module exports
__all__ = [
    "FlextAuth",
]

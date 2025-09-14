"""FLEXT Auth Service - Enterprise authentication and authorization.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import bcrypt
import jwt
from flext_core import (
    FlextContainer,
    FlextLogger,
    FlextResult,
    FlextTypes,
)

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels, create_session


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
        roles: FlextTypes.Core.StringList | None = None,
    ) -> FlextResult[FlextAuthModels.User]:
        """Register new user using domain function from models.py."""
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
        user_result = FlextAuthModels.create_user_from_request(request)

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
    ) -> FlextResult[FlextTypes.Core.Dict]:
        """Authenticate user using domain function from models.py."""
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
        auth_result = FlextAuthModels._AuthenticationService.authenticate_user(
            username, password, users_data
        )

        # Initialize default values
        user_data: dict[str, object] = {}
        session_data: dict[str, object] = {}

        # If authentication successful, store session
        if auth_result.is_success and auth_result.value is not None:
            user = auth_result.value

            # Create session data
            session_data = {}
            user_data = {"id": user.id, "username": user.username}

            if (
                user_data
                and isinstance(session_data, dict)
                and isinstance(user_data, dict)
            ):
                # Create session using domain function
                session_result = create_session(
                    user_id=str(user_data.get("id", "")),
                    ip_address=client_ip,
                    user_agent=user_agent,
                )

                if session_result.is_success:
                    session = session_result.value
                    # Override token with provided token
                    session.session_token = str(session_data.get("token", ""))

                    # Store session and update indexes
                    self._sessions[session.id] = session

                    # Add to user sessions index
                    user_id = str(user_data.get("id", ""))
                    if user_id not in self.user_sessions_index:
                        self.user_sessions_index[user_id] = []
                    self.user_sessions_index[user_id].append(session.id)

                    # Update session data with the stored session ID
                    session_data["id"] = session.id
                    session_data["session_id"] = session.id

                    # Generate JWT token for the user
                    token_result = self.generate_jwt_token(user_id)
                    if token_result.is_success:
                        session_data["jwt_token"] = token_result.value
                        session_data["tokens"] = {"access_token": token_result.value}

        # Return success only if authentication succeeded
        if auth_result.is_success and auth_result.value is not None:
            # Include tokens at top level for compatibility
            result_data = {"user": user_data, "session": session_data, "authenticated": True}
            if "jwt_token" in session_data:
                result_data["jwt_token"] = session_data["jwt_token"]
            if "tokens" in session_data:
                result_data["tokens"] = session_data["tokens"]
            return FlextResult[FlextTypes.Core.Dict].ok(result_data)
        # Return failure if authentication failed
        return FlextResult[FlextTypes.Core.Dict].fail(
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
        # Convert minutes to hours for JWT
        expires_hours = max(1, self.config.jwt_expiry_minutes // 60)

        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            secret_key=self.config.jwt_secret,
            expires_hours=expires_hours,
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

        # Convert minutes to hours for JWT
        expires_hours = max(1, expiry // 60) if expiry else 1

        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            secret_key=self.config.jwt_secret,
            expires_hours=expires_hours,
        )

        if token_result.is_failure:  # pragma: no cover
            return FlextResult[str].fail(
                token_result.error or "Token creation failed"
            )  # pragma: no cover

        return FlextResult[str].ok(token_result.value.token)

    def hash_password(self, password: str) -> str:
        """Hash password using bcrypt (legacy compatibility method).

        Args:
            password: Plain text password

        Returns:
            Hashed password string

        """
        try:
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode(), salt)
            return password_hash.decode()
        except Exception as e:
            error_msg = f"Password hashing failed: {e}"
            raise RuntimeError(error_msg) from e

    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash (legacy compatibility method).

        Args:
            password: Plain text password
            password_hash: Stored password hash

        Returns:
            True if password matches hash

        """
        try:
            return bcrypt.checkpw(password.encode(), password_hash.encode())
        except Exception:
            self._logger.exception("Password verification failed")
            return False

    def verify_token(self, token: str) -> FlextResult[FlextTypes.Core.Dict]:
        """Verify JWT token (legacy compatibility method).

        Args:
            token: JWT token string

        Returns:
            FlextResult containing token payload or error

        """
        return self.validate_token(token)

    def get_config(self) -> FlextAuthConfig:
        """Get current configuration (legacy compatibility method).

        Returns:
            Current authentication configuration

        """
        return self.config

    @property
    def token_expire_minutes(self) -> int:
        """Get token expiration in minutes (legacy compatibility)."""
        return self.config.jwt_expiry_minutes

    @property
    def bcrypt_rounds(self) -> int:
        """Get bcrypt rounds (legacy compatibility)."""
        return self.config.bcrypt_rounds

    @property
    def password_rounds(self) -> int:
        """Get password rounds (legacy compatibility)."""
        return self.config.bcrypt_rounds

    @password_rounds.setter
    def password_rounds(self, value: int) -> None:
        """Set password rounds (legacy compatibility)."""
        self.config.bcrypt_rounds = value

    @property
    def session_manager(self) -> FlextAuth:
        """Get session manager (legacy compatibility)."""
        return self

    @classmethod
    def get_global_config(cls) -> FlextResult[FlextAuthConfig]:
        """Get global configuration (legacy compatibility)."""
        try:
            config = FlextAuthConfig.get_global_instance()
            return FlextResult[FlextAuthConfig].ok(config)
        except Exception as e:
            return FlextResult[FlextAuthConfig].fail(f"Failed to get global config: {e}")

    @classmethod
    def create_with_config_overrides(
        cls,
        jwt_expiry_minutes: int | None = None,
        bcrypt_rounds: int | None = None,
    ) -> FlextResult[FlextAuth]:
        """Create FlextAuth with configuration overrides (legacy compatibility).

        Args:
            jwt_expiry_minutes: JWT token expiry in minutes
            bcrypt_rounds: Bcrypt hashing rounds
            **kwargs: Additional configuration parameters

        Returns:
            FlextAuth instance with overridden configuration

        """
        # Create config with overrides
        config_overrides: dict[str, int] = {}
        if jwt_expiry_minutes is not None:
            config_overrides["jwt_expiry_minutes"] = jwt_expiry_minutes
        if bcrypt_rounds is not None:
            config_overrides["bcrypt_rounds"] = bcrypt_rounds

        # Create config with overrides
        config_result = FlextAuthConfig.get_or_create_global(
            environment="development", **config_overrides
        )
        if config_result.is_failure:
            return FlextResult[FlextAuth].fail(
                f"Config creation failed: {config_result.error}"
            )

        # Create FlextAuth with custom config
        auth_instance = cls(config=config_result.value)
        return FlextResult[FlextAuth].ok(auth_instance)


# Module exports
__all__ = [
    "FlextAuth",
]

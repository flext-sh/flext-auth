"""FLEXT Auth API - Thin facade exposing all authentication functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import ClassVar

from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels
from flext_auth.providers import JwtAuthProvider
from flext_auth.providers.base import BaseAuthProvider
from flext_auth.registry import FlextAuthRegistry
from flext_auth.typings import FlextAuthTypes
from flext_auth.utilities import FlextAuthUtilities
from flext_core import (
    FlextContainer,
    FlextContext,
    FlextCqrs,
    FlextDispatcher,
    FlextHandlers,
    FlextLogger,
    FlextModels,
    FlextProcessors,
    FlextRegistry,
    FlextResult,
    FlextService,
    FlextUtilities,
)


class FlextAuth(FlextService[FlextAuthTypes.AuthenticationResponseDict]):
    """Enterprise authentication service - thin facade exposing all flext-auth functionality.

    This is the main entry point for all authentication operations in the FLEXT ecosystem.
    Provides secure authentication with bcrypt password hashing, JWT tokens,
    session management, and role-based access control following flext-core patterns.

    Public API:
        - register_user: Create new user with validation and secure password hashing
        - authenticate_user: Authenticate user credentials and create session
        - logout_user: Terminate user session
        - validate_token: Validate JWT token and extract payload
        - generate_token: Generate JWT token for user
        - get_user_by_username: Retrieve user by username
        - get_user_by_id: Retrieve user by ID
        - get_user_sessions: Get all active sessions for user
        - revoke_session: Revoke specific session
        - cleanup_expired_sessions: Remove expired sessions
        - quick_start: Quick start with optional REDACTED_LDAP_BIND_PASSWORD creation
        - create_with_config_overrides: Create instance with custom configuration
    """

    # Pydantic model configuration
    model_config: ClassVar[dict[str, bool]] = {
        "arbitrary_types_allowed": True,
        "validate_assignment": False,
    }

    def __init__(
        self,
        config: FlextAuthConfig | None = None,
        container: FlextContainer | None = None,
        provider_registry: FlextAuthRegistry | None = None,
        **data: object,
    ) -> None:
        """Initialize authentication service with configuration.

        Args:
            config: Authentication configuration (uses global singleton if None)
            container: DI container (uses global if None)
            provider_registry: Provider registry for multi-provider support (optional, v2.0.0 feature)
            **data: Additional data for FlextService initialization

        """
        # Initialize FlextService base class
        super().__init__(**data)

        # Use provided config or get global singleton (set as object attribute, not Pydantic field)
        object.__setattr__(
            self, "config", config or FlextAuthConfig.get_global_instance()
        )

        # Initialize dependencies (set as object attributes, not Pydantic fields)
        object.__setattr__(self, "container", container or FlextContainer.get_global())
        object.__setattr__(self, "_logger", FlextLogger(__name__))

        # Initialize advanced flext-core patterns (set as object attributes)
        object.__setattr__(self, "_dispatcher", FlextDispatcher())
        object.__setattr__(self, "_bus", self._dispatcher.bus)
        object.__setattr__(self, "_processors", self._dispatcher.processors)
        object.__setattr__(self, "_registry", FlextRegistry(self._dispatcher))
        object.__setattr__(self, "_context", FlextContext())
        object.__setattr__(self, "_cqrs", FlextCqrs())

        # Initialize provider registry (v2.0.0 feature - optional for backward compatibility)
        object.__setattr__(
            self, "_provider_registry", provider_registry or FlextAuthRegistry()
        )
        object.__setattr__(
            self, "_default_provider_name", "jwt"
        )  # Default to JWT provider

        # Initialize storage (set as object attributes)
        object.__setattr__(self, "_users", {})
        object.__setattr__(self, "_sessions", {})
        object.__setattr__(self, "username_index", {})
        object.__setattr__(self, "email_index", {})
        object.__setattr__(self, "user_sessions_index", {})

        # Initialize helper handlers using FlextHandlers patterns
        object.__setattr__(self, "_validation_handler", self._AuthValidationHelper())
        object.__setattr__(self, "_processing_handler", self._AuthProcessingHelper())
        object.__setattr__(self, "_session_handler", self._AuthSessionHelper())
        object.__setattr__(self, "_token_handler", self._AuthTokenHelper())
        object.__setattr__(self, "_factory_handler", self._AuthFactoryHelper())
        object.__setattr__(self, "_storage_handler", self._AuthStorageHelper())
        object.__setattr__(self, "_response_handler", self._AuthResponseHelper())

        # Register authentication commands and queries with FlextBus
        self._register_authentication_handlers()

        # Register validation/transformation processors
        self._register_authentication_processors()

        # Note: Event handlers can be registered externally by consumers
        # Events will be dispatched via self._dispatcher.dispatch(event_name, data)

        # Log initialization
        self._logger.info(
            f"FlextAuth initialized: token_expire_minutes={self.config.jwt_expiry_minutes}, "
            f"bcrypt_rounds={self.config.bcrypt_rounds}, jwt_secret_length={len(str(self.config.jwt_auth_secret.get_secret_value()))}"
        )

    def _register_authentication_handlers(self) -> None:
        """Register authentication command and query handlers with FlextBus and FlextRegistry.

        This method sets up the command/query infrastructure for authentication operations,
        enabling advanced FlextBus integration and handler registration.
        """
        # Create command handler instances
        register_handler = self._bus.create_simple_handler(
            self._execute_register_user_command
        )
        authenticate_handler = self._bus.create_simple_handler(
            self._execute_authenticate_command
        )
        logout_handler = self._bus.create_simple_handler(self._execute_logout_command)

        # Create query handler instances
        get_user_handler = self._bus.create_query_handler(self._execute_get_user_query)
        get_user_by_id_handler = self._bus.create_query_handler(
            self._execute_get_user_by_id_query
        )
        get_sessions_handler = self._bus.create_query_handler(
            self._execute_get_sessions_query
        )

        # Register handlers with FlextBus
        self._bus.register_handler("auth.command.register_user", register_handler)
        self._bus.register_handler("auth.command.authenticate", authenticate_handler)
        self._bus.register_handler("auth.command.logout", logout_handler)
        self._bus.register_handler("auth.query.get_user_by_username", get_user_handler)
        self._bus.register_handler("auth.query.get_user_by_id", get_user_by_id_handler)
        self._bus.register_handler("auth.query.get_user_sessions", get_sessions_handler)

        # Register handlers with FlextRegistry for service discovery
        self._registry.register_handler(register_handler)
        self._registry.register_handler(authenticate_handler)
        self._registry.register_handler(get_user_handler)

        self._logger.info(
            "Authentication command/query handlers registered with FlextBus and FlextCqrs"
        )

    def _register_authentication_processors(self) -> None:
        """Register validation and transformation processors for authentication workflows.

        This method sets up the processing pipeline for validation, normalization,
        and transformation of authentication data using FlextProcessors.

        Processors registered:
        - username_validator: Validates username format and constraints
        - email_normalizer: Normalizes email addresses to lowercase
        - password_strength_validator: Validates password complexity requirements
        - registration_data_validator: Complete registration data validation pipeline

        """
        # Validation constants (lowercase per ruff N806)
        min_username_length = 3
        max_username_length = 50
        min_password_length = 8
        max_password_length = 128

        # Username validation processor
        def validate_username(data: object) -> FlextResult[object]:
            """Validate username constraints."""
            if not isinstance(data, dict):
                return FlextResult[object].fail(
                    "Invalid data format for username validation"
                )

            username = data.get("username", "")
            if not isinstance(username, str):
                return FlextResult[object].fail("Username must be a string")

            if not username or not username.strip():
                return FlextResult[object].fail("Username cannot be empty")

            if len(username) < min_username_length:
                return FlextResult[object].fail(
                    f"Username must be at least {min_username_length} characters"
                )

            if len(username) > max_username_length:
                return FlextResult[object].fail(
                    f"Username cannot exceed {max_username_length} characters"
                )

            return FlextResult[object].ok(data)

        # Email normalization processor
        def normalize_email(data: object) -> FlextResult[object]:
            """Normalize email to lowercase."""
            if not isinstance(data, dict):
                return FlextResult[object].fail(
                    "Invalid data format for email normalization"
                )

            email = data.get("email", "")
            if not isinstance(email, str):
                return FlextResult[object].fail("Email must be a string")

            # Normalize to lowercase and strip whitespace
            normalized_email = email.lower().strip()

            # Basic email format validation
            if "@" not in normalized_email or "." not in normalized_email:
                return FlextResult[object].fail("Invalid email format")

            # Update data with normalized email
            normalized_data = {**data, "email": normalized_email}
            return FlextResult[object].ok(normalized_data)

        # Password strength validation processor
        def validate_password_strength(data: object) -> FlextResult[object]:
            """Validate password strength requirements."""
            if not isinstance(data, dict):
                return FlextResult[object].fail(
                    "Invalid data format for password validation"
                )

            password = data.get("password", "")
            if not isinstance(password, str):
                return FlextResult[object].fail("Password must be a string")

            if len(password) < min_password_length:
                return FlextResult[object].fail(
                    f"Password must be at least {min_password_length} characters"
                )

            if len(password) > max_password_length:
                return FlextResult[object].fail(
                    f"Password cannot exceed {max_password_length} characters"
                )

            # Check for at least one digit, one uppercase, one lowercase
            has_digit = any(c.isdigit() for c in password)
            has_upper = any(c.isupper() for c in password)
            has_lower = any(c.islower() for c in password)

            if not (has_digit and has_upper and has_lower):
                return FlextResult[object].fail(
                    "Password must contain at least one uppercase letter, "
                    "one lowercase letter, and one digit"
                )

            return FlextResult[object].ok(data)

        # Register processors
        self._processors.register("username_validator", validate_username)
        self._processors.register("email_normalizer", normalize_email)
        self._processors.register(
            "password_strength_validator", validate_password_strength
        )

        self._logger.info(
            "Authentication validation/transformation processors registered"
        )

    def _execute_register_user_command(
        self, command: object
    ) -> FlextResult[FlextAuthModels.User]:
        """Execute register user command via FlextBus integration."""
        if not isinstance(command, dict):
            return FlextResult[FlextAuthModels.User].fail("Invalid command format")

        roles_value = command.get("roles", [])
        roles_list = (
            list(roles_value) if isinstance(roles_value, (list, tuple)) else None
        )

        return self.register_user(
            username=str(command.get("username", "")),
            email=str(command.get("email", "")),
            password=str(command.get("password", "")),
            full_name=str(command.get("full_name"))
            if command.get("full_name")
            else None,
            roles=roles_list,
        )

    def _execute_authenticate_command(
        self, command: object
    ) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
        """Execute authenticate command via FlextBus integration."""
        if not isinstance(command, dict):
            return FlextResult[FlextAuthTypes.AuthenticationResponseDict].fail(
                "Invalid command format"
            )

        return self.authenticate_user(
            username=str(command.get("username", "")),
            password=str(command.get("password", "")),
            client_ip=str(command.get("client_ip"))
            if command.get("client_ip")
            else None,
            user_agent=str(command.get("user_agent"))
            if command.get("user_agent")
            else None,
        )

    def _execute_logout_command(self, command: object) -> FlextResult[None]:
        """Execute logout command via FlextBus integration."""
        if not isinstance(command, dict):
            return FlextResult[None].fail("Invalid command format")

        return self.logout_user(session_id=str(command.get("session_id", "")))

    def _execute_get_user_query(
        self, query: object
    ) -> FlextResult[FlextAuthModels.User | None]:
        """Execute get user by username query via FlextBus integration."""
        if not isinstance(query, dict):
            return FlextResult[FlextAuthModels.User | None].fail("Invalid query format")

        return self.get_user_by_username(username=str(query.get("username", "")))

    def _execute_get_user_by_id_query(
        self, query: object
    ) -> FlextResult[FlextAuthModels.User | None]:
        """Execute get user by ID query via FlextBus integration."""
        if not isinstance(query, dict):
            return FlextResult[FlextAuthModels.User | None].fail("Invalid query format")

        return self.get_user_by_id(user_id=str(query.get("user_id", "")))

    def _execute_get_sessions_query(
        self, query: object
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Execute get user sessions query via FlextBus integration."""
        if not isinstance(query, dict):
            return FlextResult[list[FlextAuthModels.Session]].fail(
                "Invalid query format"
            )

        return self.get_user_sessions(user_id=str(query.get("user_id", "")))

    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        full_name: str | None = None,
        roles: list[str] | None = None,
    ) -> FlextResult[FlextAuthModels.User]:
        """Register new user with FlextResult railway pattern.

        Creates a new user account with the provided credentials and information.
        Validates username and email availability, creates secure password hash,
        and stores the user with proper indexing for fast lookups.

        Args:
            username: Unique username (case insensitive)
            email: Unique email address (case insensitive)
            password: Plain text password (will be securely hashed with bcrypt)
            full_name: Optional full display name
            roles: Optional list of roles (defaults to [user])

        Returns:
            FlextResult containing the created User entity or error

        """
        # Create authentication context for request tracking
        context = FlextContext()
        context.set("operation", "register_user")
        context.set("username", username)
        context.set("email", email)
        context.set("timestamp", datetime.now(UTC).isoformat())

        self._logger.info(
            f"Starting user registration for username: {username}, email: {email}"
        )

        # Validation using FlextHandlers pattern
        validation_result = self._validation_handler.validate_registration_inputs(
            username, email, password
        )
        if validation_result.is_failure:
            self._logger.error(f"Input validation failed: {validation_result.error}")
            return FlextResult[FlextAuthModels.User].fail(
                validation_result.error or "Validation failed"
            )

        self._logger.info("Input validation passed")

        # Check username availability
        username_check = self._validation_handler.validate_username_availability(
            username, self.username_index
        )
        if username_check.is_failure:
            error_msg = username_check.error or "Username availability check failed"
            self._logger.error(f"Username availability check failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info("Username availability check passed")

        # Check email availability
        email_check = self._validation_handler.validate_email_availability(
            email, self.email_index
        )
        if email_check.is_failure:
            error_msg = email_check.error or "Email availability check failed"
            self._logger.error(f"Email availability check failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info("Email availability check passed")

        # Create user request
        request_result = self._factory_handler.create_user_request(
            username, email, password, full_name, roles
        )
        if request_result.is_failure:
            error_msg = request_result.error or "User request creation failed"
            self._logger.error(f"User request creation failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info(f"User request created: {request_result.value}")

        # Create user from request
        user_result = self._factory_handler.create_user_from_request(
            request_result.value
        )
        if user_result.is_failure:
            error_msg = user_result.error or "User creation failed"
            self._logger.error(f"User creation failed: {error_msg}")
            return FlextResult[FlextAuthModels.User].fail(error_msg)

        self._logger.info(f"User created successfully: {user_result.value}")

        # Store user and update indexes
        stored_user = self._storage_handler.store_user_and_update_indexes(
            user_result.value,
            username,
            email,
            self._users,
            self.username_index,
            self.email_index,
            self._logger,
        )

        self._logger.info(f"User registration completed successfully: {stored_user}")

        # Update context with success
        context.set("user_id", stored_user.id)
        context.set("status", "success")

        # Emit user registration event via dispatcher with context
        self._dispatcher.dispatch(
            "user.registered",
            {
                "user_id": stored_user.id,
                "username": stored_user.username,
                "email": stored_user.email,
                "roles": stored_user.roles,
                "timestamp": stored_user.created_at.isoformat(),
                "context_id": context.get("id", "unknown"),
            },
        )

        return FlextResult[FlextAuthModels.User].ok(stored_user)

    def authenticate_user(
        self,
        username: str,
        password: str,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
        """Authenticate user credentials and create session.

        Validates user credentials against stored password hash, checks account
        status (active/locked), and creates a new session with JWT token if
        authentication succeeds. Uses railway pattern for clean error propagation.

        Args:
            username: Username to authenticate (case insensitive)
            password: Plain text password to verify
            client_ip: Optional client IP address for session tracking
            user_agent: Optional user agent string for session tracking

        Returns:
            FlextResult containing AuthenticationResponseDict with user data,
            session information, and JWT token, or error information

        """
        # Create authentication context for request tracking
        context = FlextContext()
        context.set("operation", "authenticate_user")
        context.set("username", username)
        context.set("client_ip", client_ip or "unknown")
        context.set("user_agent", user_agent or "unknown")
        context.set("timestamp", datetime.now(UTC).isoformat())

        # Log authentication attempt
        self._logger.info(f"Authentication attempt for username: {username}")
        if client_ip or user_agent:
            self._logger.info(
                f"Authentication attempt from {client_ip or 'unknown'} with agent {user_agent or 'unknown'}"
            )

        # Railway pattern: Chain authentication operations
        auth_result = (
            self._processing_handler.find_user_for_auth(
                username, self.username_index, self._users
            )
            .flat_map(
                lambda user: self._processing_handler.validate_user_credentials(
                    user, password, self.config, self._users
                )
            )
            .flat_map(
                lambda user: self._session_handler.create_user_session(
                    user,
                    client_ip,
                    user_agent,
                    self._sessions,
                    self.user_sessions_index,
                )
            )
            .flat_map(
                lambda session_data: self._token_handler.generate_auth_token(
                    session_data, self
                )
            )
            .map(
                lambda auth_data: self._response_handler.build_auth_response(
                    auth_data, self.config
                )
            )
        )

        # Update context and emit authentication event if successful
        if auth_result.is_success and auth_result.value:
            context.set("user_id", auth_result.value["user"]["id"])
            context.set("status", "success")

            self._dispatcher.dispatch(
                "user.authenticated",
                {
                    "user_id": auth_result.value["user"]["id"],
                    "username": auth_result.value["user"]["username"],
                    "client_ip": client_ip,
                    "user_agent": user_agent,
                    "timestamp": datetime.now(UTC).isoformat(),
                    "context_id": context.get("id", "unknown"),
                },
            )
        else:
            context.set("status", "failed")
            context.set("error", auth_result.error or "Unknown error")

        return auth_result

    def logout_user(self, session_id: str) -> FlextResult[None]:
        """Logout user by revoking session.

        Returns:
            FlextResult[None]: Success if session revoked, error if not found

        """
        return self.revoke_session(session_id)

    def validate_token(
        self, token: str
    ) -> FlextResult[FlextAuthTypes.TokenManagement.JwtTokenPayload]:
        """Validate JWT token and return payload.

        Args:
            token: JWT token string

        Returns:
            FlextResult containing token payload or error

        """
        return self._token_handler.validate_token_complete(
            token, self.config, self._logger
        )

    def generate_token(self, user_id: str) -> str:
        """Generate JWT token for user ID.

        Returns:
            str: JWT token string

        Raises:
            RuntimeError: If user not found or token generation fails

        """
        # Get user
        user_result = self.get_user_by_id(user_id)
        if user_result.is_failure or user_result.value is None:
            msg = "User not found for token generation"
            raise RuntimeError(msg)

        # Generate token
        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            expiry_minutes=self.config.jwt_expiry_minutes,
            token_type=FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            jwt_secret=str(self.config.jwt_auth_secret.get_secret_value()),
        )

        if token_result.is_failure:
            msg = f"Failed to generate token: {token_result.error}"
            raise RuntimeError(msg)

        return token_result.value.token

    def get_user_by_username(
        self,
        username: str,
    ) -> FlextResult[FlextAuthModels.User | None]:
        """Get user by username (case insensitive).

        Returns:
            FlextResult[FlextAuthModels.User | None]: Success with user or None

        """
        user_id = self.username_index.get(username.lower())
        if not user_id:
            return FlextResult[FlextAuthModels.User | None].ok(None)

        user = self._users.get(user_id)
        return FlextResult[FlextAuthModels.User | None].ok(user)

    def get_user_by_id(self, user_id: str) -> FlextResult[FlextAuthModels.User | None]:
        """Get user by ID.

        Returns:
            FlextResult[FlextAuthModels.User | None]: Success with user or None

        """
        user = self._users.get(user_id)
        return FlextResult[FlextAuthModels.User | None].ok(user)

    def get_user_sessions(
        self,
        user_id: str,
    ) -> FlextResult[list[FlextAuthModels.Session]]:
        """Get all active sessions for user.

        Returns:
            FlextResult[list[FlextAuthModels.Session]]: Success with sessions

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
            FlextResult[None]: Success if session revoked, error if not found

        """
        # Create context for session revocation
        context = FlextContext()
        context.set("operation", "revoke_session")
        context.set("session_id", session_id)
        context.set("timestamp", datetime.now(UTC).isoformat())

        session = self._sessions.get(session_id)
        if not session:
            context.set("status", "failed")
            context.set("error", "Session not found")
            return FlextResult[None].fail(
                "Session not found",
                error_code=FlextAuthConstants.ErrorCodes.SESSION_NOT_FOUND,
            )

        user_id = session.user_id
        context.set("user_id", user_id)
        session.revoke()
        self._logger.info(f"Session revoked: {session_id}")

        # Update context with success
        context.set("status", "success")

        # Emit session revoked event via dispatcher with context
        self._dispatcher.dispatch(
            "session.revoked",
            {
                "session_id": session_id,
                "user_id": user_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "context_id": context.get("id", "unknown"),
            },
        )

        # Emit user logged out event via dispatcher with context
        self._dispatcher.dispatch(
            "user.logged_out",
            {
                "session_id": session_id,
                "user_id": user_id,
                "timestamp": datetime.now(UTC).isoformat(),
                "context_id": context.get("id", "unknown"),
            },
        )

        return FlextResult[None].ok(None)

    def cleanup_expired_sessions(self) -> FlextResult[int]:
        """Remove expired sessions and return count.

        Returns:
            FlextResult[int]: Success with count of cleaned up sessions

        """
        expired_sessions = [
            session_id
            for session_id, session in self._sessions.items()
            if session.is_expired or not session.is_active
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

    @classmethod
    def quick_start(
        cls,
        *,
        create_REDACTED_LDAP_BIND_PASSWORD: bool = True,
        REDACTED_LDAP_BIND_PASSWORD_username: str = FlextAuthConstants.Roles.ADMIN,
        REDACTED_LDAP_BIND_PASSWORD_password: str = FlextAuthConstants.DEFAULT_ADMIN_PASSWORD,
    ) -> FlextAuth:
        """Quick start with simplified setup.

        Returns:
            FlextAuth: Configured authentication service instance

        Raises:
            RuntimeError: If REDACTED_LDAP_BIND_PASSWORD user creation fails

        """
        # Create FlextAuth instance
        auth = cls()

        # Conditionally create REDACTED_LDAP_BIND_PASSWORD user
        if create_REDACTED_LDAP_BIND_PASSWORD:
            REDACTED_LDAP_BIND_PASSWORD_result = auth.register_user(
                username=REDACTED_LDAP_BIND_PASSWORD_username,
                email=f"{REDACTED_LDAP_BIND_PASSWORD_username}@example.com",
                password=REDACTED_LDAP_BIND_PASSWORD_password,
                roles=[FlextAuthConstants.Roles.ADMIN],
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
        """Create FlextAuth instance with configuration overrides.

        Args:
            jwt_expiry_minutes: JWT token expiry time in minutes
            bcrypt_rounds: Number of bcrypt rounds for password hashing
            max_failed_attempts: Maximum failed login attempts before lockout
            _lockout_duration_minutes: Account lockout duration in minutes

        Returns:
            FlextResult containing FlextAuth instance or error

        """
        # Create config
        try:
            config = FlextAuthConfig.create_for_environment("production")
        except Exception as e:
            return FlextResult[FlextAuth].fail(f"Failed to create config: {e}")

        # Apply overrides
        if jwt_expiry_minutes is not None:
            config.jwt_expiry_minutes = jwt_expiry_minutes
        if bcrypt_rounds is not None:
            config.bcrypt_rounds = bcrypt_rounds
        if max_failed_attempts is not None:
            config.max_login_attempts = max_failed_attempts

        # Create FlextAuth instance
        auth = cls(config=config)

        return FlextResult[FlextAuth].ok(auth)

    @classmethod
    def with_jwt(
        cls,
        secret_key: str,
        algorithm: str = "HS256",
        access_token_expiry_minutes: int = 30,
        refresh_token_expiry_days: int = 7,
        **kwargs: object,
    ) -> FlextAuth:
        """Create FlextAuth instance with JWT provider (v2.0.0 API).

        This is the recommended factory method for JWT authentication in v2.0.0+.
        It creates a provider registry with a JWT provider and returns a
        configured FlextAuth instance.

        Args:
            secret_key: Secret key for JWT signing
            algorithm: JWT algorithm (default: HS256)
            access_token_expiry_minutes: Access token lifetime (default: 30)
            refresh_token_expiry_days: Refresh token lifetime (default: 7)
            **kwargs: Additional arguments passed to FlextAuth constructor

        Returns:
            FlextAuth: Configured authentication service with JWT provider

        Example:
            >>> auth = FlextAuth.with_jwt(secret_key="your-secret-key")
            >>> result = auth.authenticate_user("user", "password")

        Note:
            This is the v2.0.0 API. The v1.0.0 quick_start() method is still
            supported for backward compatibility but is deprecated.

        """
        # Create JWT provider configuration
        jwt_config = {
            "secret_key": secret_key,
            "algorithm": algorithm,
            "access_token_expiry_minutes": access_token_expiry_minutes,
            "refresh_token_expiry_days": refresh_token_expiry_days,
        }

        # Create JWT provider
        jwt_provider = JwtAuthProvider(jwt_config)

        # Create provider registry
        registry = FlextAuthRegistry()
        registry.register("jwt", jwt_provider)

        # Create FlextAuth config
        config = FlextAuthConfig.create_for_environment("production")

        # Create FlextAuth instance with registry
        return cls(config=config, provider_registry=registry, **kwargs)

    @classmethod
    def with_provider(
        cls,
        provider: BaseAuthProvider,
        provider_name: str = "custom",
        config: FlextAuthConfig | None = None,
        **kwargs: object,
    ) -> FlextAuth:
        """Create FlextAuth instance with a custom provider (v2.0.0 API).

        This factory method allows using any authentication provider that
        implements the BaseAuthProvider protocol.

        Args:
            provider: Authentication provider instance
            provider_name: Name for the provider in registry (default: "custom")
            config: Optional FlextAuth configuration
            **kwargs: Additional arguments passed to FlextAuth constructor

        Returns:
            FlextAuth: Configured authentication service with custom provider

        Example:
            >>> from flext_auth.providers import OAuth2AuthProvider
            >>> oauth_provider = OAuth2AuthProvider(oauth_config)
            >>> auth = FlextAuth.with_provider(oauth_provider, provider_name="oauth2")
            >>> result = auth.authenticate(credentials, provider="oauth2")

        """
        # Create provider registry
        registry = FlextAuthRegistry()
        registry.register(provider_name, provider)

        # Use provided config or create default
        if config is None:
            config = FlextAuthConfig.create_for_environment("production")

        # Create FlextAuth instance with registry
        auth = cls(config=config, provider_registry=registry, **kwargs)
        setattr(auth, "_default_provider_name", provider_name)

        return auth

    @classmethod
    def with_registry(
        cls,
        registry: FlextAuthRegistry,
        default_provider: str = "jwt",
        config: FlextAuthConfig | None = None,
        **kwargs: object,
    ) -> FlextAuth:
        """Create FlextAuth instance with a provider registry (v2.0.0 API).

        This factory method is used for multi-provider scenarios where you
        have multiple authentication providers registered.

        Args:
            registry: Pre-configured provider registry
            default_provider: Default provider name (default: "jwt")
            config: Optional FlextAuth configuration
            **kwargs: Additional arguments passed to FlextAuth constructor

        Returns:
            FlextAuth: Configured authentication service with provider registry

        Example:
            >>> registry = FlextAuthRegistry()
            >>> registry.register("jwt", JwtAuthProvider(jwt_config))
            >>> registry.register("oauth2", OAuth2AuthProvider(oauth_config))
            >>> registry.register("saml", SamlAuthProvider(saml_config))
            >>>
            >>> auth = FlextAuth.with_registry(registry, default_provider="jwt")
            >>> jwt_result = auth.authenticate(creds, provider="jwt")
            >>> oauth_result = auth.authenticate(creds, provider="oauth2")

        """
        # Use provided config or create default
        if config is None:
            config = FlextAuthConfig.create_for_environment("production")

        # Create FlextAuth instance with registry
        auth = cls(config=config, provider_registry=registry, **kwargs)
        setattr(auth, "_default_provider_name", default_provider)

        return auth

    def list_providers(self) -> list[str]:
        """List all registered authentication providers (v2.0.0 API).

        Returns:
            list[str]: List of registered provider names

        Example:
            >>> auth = FlextAuth.with_registry(registry)
            >>> providers = auth.list_providers()
            >>> print(f"Available providers: {', '.join(providers)}")

        """
        return self._provider_registry.list_providers()

    def get_provider(self, name: str) -> FlextResult[BaseAuthProvider]:
        """Get a registered authentication provider (v2.0.0 API).

        Args:
            name: Provider name

        Returns:
            FlextResult[BaseAuthProvider]: Provider instance or error

        Example:
            >>> result = auth.get_provider("jwt")
            >>> if result.is_success:
            ...     provider = result.unwrap()
            ...     caps = provider.supports()

        """
        return self._provider_registry.get(name)

    def get_provider_capabilities(self, name: str) -> FlextResult[set[str]]:
        """Get capabilities of a registered provider (v2.0.0 API).

        Args:
            name: Provider name

        Returns:
            FlextResult[set[str]]: Set of capabilities or error

        Example:
            >>> result = auth.get_provider_capabilities("oauth2")
            >>> if result.is_success:
            ...     caps = result.unwrap()
            ...     if "refresh" in caps:
            ...         print("Provider supports token refresh")

        """
        return self._provider_registry.get_capabilities(name)

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
            return FlextResult[str].fail("User not found for JWT generation")

        token_result = FlextAuthModels.AuthToken.create_jwt_token(
            user_id=user_id,
            expiry_minutes=expiry or self.config.jwt_expiry_minutes,
            token_type=FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
            jwt_secret=str(self.config.jwt_auth_secret.get_secret_value()),
        )

        if token_result.is_failure:
            return FlextResult[str].fail(token_result.error or "Token creation failed")

        return FlextResult[str].ok(token_result.value.token)

    @property
    def token_expire_minutes(self) -> int:
        """Get JWT token expiry minutes from configuration."""
        return self.config.jwt_expiry_minutes

    @property
    def bcrypt_rounds(self) -> int:
        """Get bcrypt rounds from configuration."""
        return self.config.bcrypt_rounds

    @property
    def bus(self) -> object:
        """Access FlextBus for advanced command/query operations."""
        return self._bus

    @property
    def registry(self) -> FlextRegistry:
        """Access FlextRegistry for handler registration and service discovery."""
        return self._registry

    @property
    def context(self) -> FlextContext:
        """Access FlextContext for request context management."""
        return self._context

    @property
    def processors(self) -> FlextProcessors:
        """Access FlextProcessors for validation and transformation pipelines."""
        return self._processors

    def validate_registration_data(
        self, username: str, email: str, password: str
    ) -> FlextResult[dict[str, str]]:
        """Validate and normalize registration data using processor pipeline.

        This method runs the registration data through validation and transformation processors:
        1. Email normalization (lowercase and trim)
        2. Username validation (length, format)
        3. Password strength validation (complexity requirements)

        Args:
            username: Username to validate
            email: Email to normalize and validate
            password: Password to validate for strength

        Returns:
            FlextResult containing validated and normalized data or validation errors

        """
        # Create data dict for processing
        data = {
            "username": username,
            "email": email,
            "password": password,
        }

        # Run through processor pipeline: email normalization -> username validation -> password strength
        email_result = self._processors.process("email_normalizer", data)
        if email_result.is_failure:
            return FlextResult[dict[str, str]].fail(
                f"Email validation failed: {email_result.error}"
            )

        username_result = self._processors.process(
            "username_validator", email_result.value
        )
        if username_result.is_failure:
            return FlextResult[dict[str, str]].fail(
                f"Username validation failed: {username_result.error}"
            )

        password_result = self._processors.process(
            "password_strength_validator", username_result.value
        )
        if password_result.is_failure:
            return FlextResult[dict[str, str]].fail(
                f"Password validation failed: {password_result.error}"
            )

        # All validations passed, return normalized data
        validated_data = password_result.value
        if isinstance(validated_data, dict):
            return FlextResult[dict[str, str]].ok(validated_data)

        return FlextResult[dict[str, str]].fail(
            "Processor pipeline returned invalid data format"
        )

    def execute_command(self, command: object) -> FlextResult[object]:
        """Execute authentication command via FlextBus.

        Args:
            command: Command object to execute

        Returns:
            FlextResult containing command execution result

        """
        try:
            return self._bus.execute(command)
        except Exception as e:
            return FlextResult[object].fail(f"Command execution failed: {e}")

    def execute_query(self, query: object) -> FlextResult[object]:
        """Execute authentication query via FlextBus.

        Args:
            query: Query object to execute

        Returns:
            FlextResult containing query result

        """
        try:
            return self._bus.execute(query)
        except Exception as e:
            return FlextResult[object].fail(f"Query execution failed: {e}")

    def execute(
        self, operation: str, **params: object
    ) -> FlextResult[FlextAuthTypes.AuthenticationResponseDict]:
        """Execute authentication operations (FlextService abstract method implementation).

        This method implements the abstract execute() method from FlextService,
        providing a unified interface for all authentication operations.

        Args:
            operation: Operation name ('register', 'authenticate', 'logout', etc.)
            **params: Operation-specific parameters

        Returns:
            FlextResult[FlextAuthTypes.AuthenticationResponseDict]: Operation result

        """
        match operation:
            case "register":
                username = str(params.get("username", ""))
                email = str(params.get("email", ""))
                password = str(params.get("password", ""))
                full_name = params.get("full_name")
                roles = params.get("roles")
                result = self.register_user(
                    username,
                    email,
                    password,
                    full_name=str(full_name) if full_name else None,
                    roles=list(roles) if isinstance(roles, list) else None,
                )
                # Convert User result to AuthenticationResponseDict format
                if result.is_success:
                    user = result.value
                    return FlextResult[FlextAuthTypes.AuthenticationResponseDict].ok({
                        "user": {
                            "id": user.id,
                            "username": user.username,
                            "email": user.email,
                            "full_name": user.full_name,
                            "is_active": user.is_active,
                            "roles": user.roles,
                            "created_at": user.created_at,
                            "updated_at": user.updated_at,
                            "last_login": user.last_login,
                        },
                        "session": {
                            "id": "",
                            "user_id": user.id,
                            "session_token": "",
                            "expires_at": user.created_at,
                            "created_at": user.created_at,
                            "last_accessed_at": user.created_at,
                            "is_active": False,
                            "ip_address": None,
                            "user_agent": None,
                        },
                        "jwt_token": "",
                        "authenticated": False,
                        "success": True,
                    })
                return FlextResult[FlextAuthTypes.AuthenticationResponseDict].fail(
                    result.error or "Registration failed"
                )

            case "authenticate":
                username = str(params.get("username", ""))
                password = str(params.get("password", ""))
                client_ip = params.get("client_ip")
                user_agent = params.get("user_agent")
                return self.authenticate_user(
                    username,
                    password,
                    client_ip=str(client_ip) if client_ip else None,
                    user_agent=str(user_agent) if user_agent else None,
                )

            case "logout":
                session_id = str(params.get("session_id", ""))
                result = self.logout_user(session_id)
                # Convert None result to AuthenticationResponseDict format
                if result.is_success:
                    return FlextResult[FlextAuthTypes.AuthenticationResponseDict].ok({
                        "user": {
                            "id": "",
                            "username": "",
                            "email": "",
                            "full_name": None,
                            "is_active": False,
                            "roles": [],
                            "created_at": datetime.now(UTC),
                            "updated_at": datetime.now(UTC),
                            "last_login": None,
                        },
                        "session": {
                            "id": session_id,
                            "user_id": "",
                            "session_token": "",
                            "expires_at": datetime.now(UTC),
                            "created_at": datetime.now(UTC),
                            "last_accessed_at": datetime.now(UTC),
                            "is_active": False,
                            "ip_address": None,
                            "user_agent": None,
                        },
                        "jwt_token": "",
                        "authenticated": False,
                        "success": True,
                    })
                return FlextResult[FlextAuthTypes.AuthenticationResponseDict].fail(
                    result.error or "Logout failed"
                )

            case _:
                return FlextResult[FlextAuthTypes.AuthenticationResponseDict].fail(
                    f"Unknown operation: {operation}"
                )

    # Nested helper classes for internal organization - now using FlextHandlers patterns
    class _AuthValidationHelper(FlextHandlers):
        """Authentication validation handler using FlextHandlers patterns.

        Extends FlextHandlers to provide validation with built-in logging,
        metrics tracking, and handler lifecycle management.
        """

        def __init__(self) -> None:
            """Initialize validation handler with default config."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id="auth_validation",
                handler_name="AuthValidationHandler",
            )
            super().__init__(config=config)

        def handle(self, data: dict[str, object]) -> FlextResult[None]:
            """Handle validation using FlextHandlers pattern (implements abstract method).

            Args:
                data: Validation data containing 'operation' and parameters

            Returns:
                FlextResult[None]: Success or validation error

            """
            operation = data.get("operation", "")

            match operation:
                case "registration_inputs":
                    return self.validate_registration_inputs(
                        str(data.get("username", "")),
                        str(data.get("email", "")),
                        str(data.get("password", "")),
                    )
                case "username_availability":
                    return self.validate_username_availability(
                        str(data.get("username", "")),
                        dict(data.get("username_index", {})),
                    )
                case "email_availability":
                    return self.validate_email_availability(
                        str(data.get("email", "")), dict(data.get("email_index", {}))
                    )
                case _:
                    return FlextResult[None].fail(
                        f"Unknown validation operation: {operation}"
                    )

        def validate_registration_inputs(
            self, username: str, email: str, password: str
        ) -> FlextResult[None]:
            """Validate registration inputs using FlextUtilities with handler logging.

            Returns:
                FlextResult[None]: Success if valid, error otherwise

            """
            # Use FlextHandlers logging
            log_config = FlextModels.LogOperation(
                message="Validating registration inputs",
                operation="validate_registration_inputs",
                context={"username": username, "email": email},
            )
            self.log_operation(log_config)

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

        def validate_username_availability(
            self, username: str, username_index: dict[str, str]
        ) -> FlextResult[None]:
            """Validate username is available with handler logging.

            Returns:
                FlextResult[None]: Success if available, error if taken

            """
            log_config = FlextModels.LogOperation(
                message="Validating username availability",
                operation="validate_username_availability",
                context={"username": username},
            )
            self.log_operation(log_config)

            if username.lower() in username_index:
                return FlextResult[None].fail(
                    "Username already exists",
                    error_code=FlextAuthConstants.ErrorCodes.USERNAME_TAKEN,
                )
            return FlextResult[None].ok(None)

        def validate_email_availability(
            self, email: str, email_index: dict[str, str]
        ) -> FlextResult[None]:
            """Validate email is available with handler logging.

            Returns:
                FlextResult[None]: Success if available, error if taken

            """
            log_config = FlextModels.LogOperation(
                message="Validating email availability",
                operation="validate_email_availability",
                context={"email": email},
            )
            self.log_operation(log_config)

            if email.lower() in email_index:
                return FlextResult[None].fail(
                    "Email already exists",
                    error_code=FlextAuthConstants.ErrorCodes.EMAIL_TAKEN,
                )
            return FlextResult[None].ok(None)

    class _AuthFactoryHelper(FlextHandlers):
        """Authentication factory handler using FlextHandlers patterns.

        Extends FlextHandlers to provide object creation with built-in
        logging, metrics tracking, and handler lifecycle management.
        """

        def __init__(self) -> None:
            """Initialize factory handler."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id="auth_factory",
                handler_name="AuthFactoryHandler",
            )
            super().__init__(config=config)

        def handle(self, data: dict[str, object]) -> FlextResult[object]:
            """Handle factory operations using FlextHandlers pattern.

            Args:
                data: Factory data containing 'operation' and parameters

            Returns:
                FlextResult[object]: Success with created object or error

            """
            operation = data.get("operation", "")

            match operation:
                case "create_user_request":
                    return self.create_user_request(
                        str(data.get("username", "")),
                        str(data.get("email", "")),
                        str(data.get("password", "")),
                        str(data.get("full_name")) if data.get("full_name") else None,
                        list(data.get("roles", [])) if data.get("roles") else None,
                    )
                case "create_user":
                    request = data.get("request")
                    if not isinstance(request, FlextAuthModels.UserCreationRequest):
                        return FlextResult[object].fail("Invalid user creation request")
                    return self.create_user_from_request(request)
                case _:
                    return FlextResult[object].fail(
                        f"Unknown factory operation: {operation}"
                    )

        def create_user_request(
            self,
            username: str,
            email: str,
            password: str,
            full_name: str | None,
            roles: list[str] | None,
        ) -> FlextResult[FlextAuthModels.UserCreationRequest]:
            """Create user request using FlextModels with handler logging.

            Returns:
                FlextResult[FlextAuthModels.UserCreationRequest]: Success with request

            """
            log_config = FlextModels.LogOperation(
                message="Creating user request",
                operation="create_user_request",
                context={"username": username, "email": email},
            )
            self.log_operation(log_config)

            user_request = FlextAuthModels.UserCreationRequest(
                username=username,
                email=email,
                password=password,
                full_name=full_name,
                roles=roles or [FlextAuthConstants.Roles.USER],
            )
            return FlextResult[FlextAuthModels.UserCreationRequest].ok(user_request)

        def create_user_from_request(
            self,
            request: FlextAuthModels.UserCreationRequest,
        ) -> FlextResult[FlextAuthModels.User]:
            """Create user from request using models with handler logging.

            Returns:
                FlextResult[FlextAuthModels.User]: Success with user

            """
            log_config = FlextModels.LogOperation(
                message="Creating user from request",
                operation="create_user_from_request",
                context={"username": request.username, "email": request.email},
            )
            self.log_operation(log_config)

            return FlextAuthModels.User.create_user(request)

    class _AuthStorageHelper(FlextHandlers):
        """Authentication storage handler using FlextHandlers patterns.

        Extends FlextHandlers to provide storage operations with built-in
        logging, metrics tracking, and handler lifecycle management.
        """

        def __init__(self) -> None:
            """Initialize storage handler."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id="auth_storage",
                handler_name="AuthStorageHandler",
            )
            super().__init__(config=config)

        def handle(self, data: dict[str, object]) -> FlextResult[object]:
            """Handle storage operations using FlextHandlers pattern.

            Args:
                data: Storage data containing 'operation' and parameters

            Returns:
                FlextResult[object]: Success with stored data or error

            """
            operation = data.get("operation", "")

            match operation:
                case "store_user":
                    user = data.get("user")
                    if not isinstance(user, FlextAuthModels.User):
                        return FlextResult[object].fail("Invalid user data")
                    return FlextResult[object].ok(
                        self.store_user_and_update_indexes(
                            user,
                            str(data.get("username", "")),
                            str(data.get("email", "")),
                            dict(data.get("users", {})),
                            dict(data.get("username_index", {})),
                            dict(data.get("email_index", {})),
                            data.get("logger") or FlextLogger(__name__),
                        )
                    )
                case _:
                    return FlextResult[object].fail(
                        f"Unknown storage operation: {operation}"
                    )

        def store_user_and_update_indexes(
            self,
            user: FlextAuthModels.User,
            username: str,
            email: str,
            users: dict[str, FlextAuthModels.User],
            username_index: dict[str, str],
            email_index: dict[str, str],
            logger: FlextLogger,
        ) -> FlextAuthModels.User:
            """Store user and update indexes with handler logging.

            Returns:
                FlextAuthModels.User: The stored user entity

            """
            log_config = FlextModels.LogOperation(
                message="Storing user and updating indexes",
                operation="store_user_and_update_indexes",
                context={"user_id": user.id, "username": username, "email": email},
            )
            self.log_operation(log_config)

            logger.info(
                f"_store_user_and_update_indexes called with user={user}, username={username}, email={email}"
            )

            # Store user and update indexes
            users[user.id] = user
            username_index[username.lower()] = user.id
            email_index[email.lower()] = user.id

            logger.info(f"User registered successfully: {username} (ID: {user.id})")

            return user

    class _AuthProcessingHelper(FlextHandlers):
        """Authentication processing handler using FlextHandlers patterns.

        Extends FlextHandlers to provide authentication processing with built-in
        logging, metrics tracking, and handler lifecycle management.
        """

        def __init__(self) -> None:
            """Initialize authentication processing handler."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id="auth_processing",
                handler_name="AuthProcessingHandler",
            )
            super().__init__(config=config)

        def handle(self, data: dict[str, object]) -> FlextResult[object]:
            """Handle authentication processing using FlextHandlers pattern.

            Args:
                data: Processing data containing 'operation' and parameters

            Returns:
                FlextResult[object]: Success with processed data or error

            """
            operation = data.get("operation", "")

            match operation:
                case "find_user":
                    return self.find_user_for_auth(
                        str(data.get("username", "")),
                        dict(data.get("username_index", {})),
                        dict(data.get("users", {})),
                    )
                case "validate_credentials":
                    user = data.get("user")
                    if not isinstance(user, FlextAuthModels.User):
                        return FlextResult[object].fail("Invalid user data")
                    config = data.get("config")
                    if not isinstance(config, FlextAuthConfig):
                        return FlextResult[object].fail("Invalid config data")
                    return self.validate_user_credentials(
                        user,
                        str(data.get("password", "")),
                        config,
                        dict(data.get("users", {})),
                    )
                case _:
                    return FlextResult[object].fail(
                        f"Unknown processing operation: {operation}"
                    )

        def find_user_for_auth(
            self,
            username: str,
            username_index: dict[str, str],
            users: dict[str, FlextAuthModels.User],
        ) -> FlextResult[FlextAuthModels.User]:
            """Find and validate user for authentication with handler logging.

            Returns:
                FlextResult[FlextAuthModels.User]: Success with user or error

            """
            log_config = FlextModels.LogOperation(
                message="Finding user for authentication",
                operation="find_user_for_auth",
                context={"username": username},
            )
            self.log_operation(log_config)

            if not username or not username.strip():
                return FlextResult[FlextAuthModels.User].fail(
                    "Username cannot be empty",
                    error_code=FlextAuthConstants.ErrorCodes.INVALID_CREDENTIALS,
                )

            user_id = username_index.get(username.lower())
            if not user_id:
                return FlextResult[FlextAuthModels.User].fail(
                    "Invalid credentials",
                    error_code=FlextAuthConstants.ErrorCodes.INVALID_CREDENTIALS,
                )

            user = users.get(user_id)
            if not user:
                return FlextResult[FlextAuthModels.User].fail(
                    "Invalid credentials",
                    error_code=FlextAuthConstants.ErrorCodes.INVALID_CREDENTIALS,
                )

            return FlextResult[FlextAuthModels.User].ok(user)

        def validate_user_credentials(
            self,
            user: FlextAuthModels.User,
            password: str,
            config: FlextAuthConfig,
            users: dict[str, FlextAuthModels.User],
        ) -> FlextResult[FlextAuthModels.User]:
            """Validate user credentials and account status with handler logging.

            Returns:
                FlextResult[FlextAuthModels.User]: Success with user or error

            """
            log_config = FlextModels.LogOperation(
                message="Validating user credentials",
                operation="validate_user_credentials",
                context={"user_id": user.id, "username": user.username},
            )
            self.log_operation(log_config)

            if not password or not password.strip():
                return FlextResult[FlextAuthModels.User].fail(
                    "Password cannot be empty",
                    error_code=FlextAuthConstants.ErrorCodes.INVALID_CREDENTIALS,
                )

            # Check if account is locked
            if user.is_locked:
                return FlextResult[FlextAuthModels.User].fail(
                    "Account is locked due to too many failed attempts",
                    error_code=FlextAuthConstants.ErrorCodes.ACCOUNT_LOCKED,
                )

            # Check if account is active
            if not user.can_login:
                return FlextResult[FlextAuthModels.User].fail(
                    "Account is not active",
                    error_code=FlextAuthConstants.ErrorCodes.ACCOUNT_DISABLED,
                )

            # Verify password using railway pattern
            return user.verify_password(password).flat_map(
                lambda is_valid: self.handle_password_verification(
                    user, is_valid=is_valid, config=config, users=users
                )
            )

        def handle_password_verification(
            self,
            user: FlextAuthModels.User,
            *,
            is_valid: bool,
            config: FlextAuthConfig,
            users: dict[str, FlextAuthModels.User],
        ) -> FlextResult[FlextAuthModels.User]:
            """Handle password verification result.

            Returns:
                FlextResult[FlextAuthModels.User]: Success with user or error

            """
            if not is_valid:
                # Record failed login attempt
                user.record_failed_login()
                # Update the user in storage to persist failed login state
                users[user.id] = user

                return FlextResult[FlextAuthModels.User].fail(
                    "Invalid credentials"
                    if user.failed_login_attempts < config.max_login_attempts
                    else "Account locked due to too many failed attempts"
                )

            # Successful authentication
            user.record_successful_login()
            # Update the user in storage to persist successful login state
            users[user.id] = user

            return FlextResult[FlextAuthModels.User].ok(user)

    class _AuthSessionHelper(FlextHandlers):
        """Authentication session management handler using FlextHandlers patterns.

        Extends FlextHandlers to provide session management with built-in
        logging, metrics tracking, and handler lifecycle management.
        """

        def __init__(self) -> None:
            """Initialize session management handler."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id="auth_session",
                handler_name="AuthSessionHandler",
            )
            super().__init__(config=config)

        def handle(self, data: dict[str, object]) -> FlextResult[object]:
            """Handle session management using FlextHandlers pattern.

            Args:
                data: Session data containing 'operation' and parameters

            Returns:
                FlextResult[object]: Success with session data or error

            """
            operation = data.get("operation", "")

            match operation:
                case "create_session":
                    user = data.get("user")
                    if not isinstance(user, FlextAuthModels.User):
                        return FlextResult[object].fail("Invalid user data")
                    return self.create_user_session(
                        user,
                        str(data.get("client_ip")) if data.get("client_ip") else None,
                        str(data.get("user_agent")) if data.get("user_agent") else None,
                        dict(data.get("sessions", {})),
                        dict(data.get("user_sessions_index", {})),
                    )
                case _:
                    return FlextResult[object].fail(
                        f"Unknown session operation: {operation}"
                    )

        def create_user_session(
            self,
            user: FlextAuthModels.User,
            client_ip: str | None,
            user_agent: str | None,
            sessions: dict[str, FlextAuthModels.Session],
            user_sessions_index: dict[str, list[str]],
        ) -> FlextResult[dict[str, object]]:
            """Create session for authenticated user with handler logging.

            Returns:
                FlextResult[dict[str, object]]: Success with session data

            """
            log_config = FlextModels.LogOperation(
                message="Creating user session",
                operation="create_user_session",
                context={
                    "user_id": user.id,
                    "username": user.username,
                    "client_ip": client_ip or "unknown",
                },
            )
            self.log_operation(log_config)

            return FlextAuthModels.Session.create_session(
                user_id=user.id,
                ip_address=client_ip,
                user_agent=user_agent,
            ).map(
                lambda session: self.store_session_and_build_data(
                    user, session, sessions, user_sessions_index
                )
            )

        def store_session_and_build_data(
            self,
            user: FlextAuthModels.User,
            session: FlextAuthModels.Session,
            sessions: dict[str, FlextAuthModels.Session],
            user_sessions_index: dict[str, list[str]],
        ) -> dict[str, object]:
            """Store session and prepare session data.

            Returns:
                dict[str, object]: Session data dictionary

            """
            # Store session and update indexes
            sessions[session.id] = session

            # Add to user sessions index
            if user.id not in user_sessions_index:
                user_sessions_index[user.id] = []
            user_sessions_index[user.id].append(session.id)

            # Note: Event emission for session.created happens in authenticate_user after full auth flow
            return {"user": user, "session": session}

    class _AuthTokenHelper(FlextHandlers):
        """Authentication token handler using FlextHandlers patterns.

        Extends FlextHandlers to provide token management with built-in
        logging, metrics tracking, and handler lifecycle management.
        """

        def __init__(self) -> None:
            """Initialize token management handler."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id="auth_token",
                handler_name="AuthTokenHandler",
            )
            super().__init__(config=config)

        def handle(self, data: dict[str, object]) -> FlextResult[object]:
            """Handle token management using FlextHandlers pattern.

            Args:
                data: Token data containing 'operation' and parameters

            Returns:
                FlextResult[object]: Success with token data or error

            """
            operation = data.get("operation", "")

            match operation:
                case "generate_token":
                    session_data = data.get("session_data")
                    if not isinstance(session_data, dict):
                        return FlextResult[object].fail("Invalid session data")
                    auth_instance = data.get("auth_instance")
                    if not isinstance(auth_instance, FlextAuth):
                        return FlextResult[object].fail("Invalid auth instance")
                    return self.generate_auth_token(session_data, auth_instance)
                case "validate_token":
                    token = data.get("token")
                    if not isinstance(token, str):
                        return FlextResult[object].fail("Invalid token")
                    config = data.get("config")
                    if not isinstance(config, FlextAuthConfig):
                        return FlextResult[object].fail("Invalid config")
                    logger = data.get("logger")
                    if not isinstance(logger, FlextLogger):
                        return FlextResult[object].fail("Invalid logger")
                    return self.validate_token_complete(token, config, logger)
                case _:
                    return FlextResult[object].fail(
                        f"Unknown token operation: {operation}"
                    )

        def generate_auth_token(
            self, session_data: dict[str, object], auth_instance: FlextAuth
        ) -> FlextResult[dict[str, object]]:
            """Generate JWT token for authenticated session with handler logging.

            Returns:
                FlextResult[dict[str, object]]: Success with auth data

            """
            user = session_data["user"]

            if not isinstance(user, FlextAuthModels.User):
                return FlextResult[dict[str, object]].fail(
                    "Invalid user data in session"
                )

            log_config = FlextModels.LogOperation(
                message="Generating authentication token",
                operation="generate_auth_token",
                context={"user_id": user.id, "username": user.username},
            )
            self.log_operation(log_config)

            return auth_instance.generate_jwt_token(user.id).map(
                lambda jwt_token: {**session_data, "jwt_token": jwt_token}
            )

        def validate_token_complete(
            self, token: str, config: FlextAuthConfig, logger: FlextLogger
        ) -> FlextResult[FlextAuthTypes.TokenManagement.JwtTokenPayload]:
            """Validate JWT token and return payload with handler logging.

            Returns:
                FlextResult containing token payload or error

            """
            token_prefix_length = 20
            log_config = FlextModels.LogOperation(
                message="Validating JWT token",
                operation="validate_token_complete",
                context={
                    "token_prefix": token[:token_prefix_length]
                    if len(token) > token_prefix_length
                    else token
                },
            )
            self.log_operation(log_config)

            # Use FlextUtilities for input validation
            token_validation = FlextUtilities.Validation.validate_string(
                token, field_name="token"
            )
            if token_validation.is_failure:
                return FlextResult[FlextAuthTypes.TokenManagement.JwtTokenPayload].fail(
                    "Token cannot be empty"
                )

            # Clean token
            clean_token = token.removeprefix(FlextAuthConstants.Jwt.BEARER_PREFIX)

            # Basic format validation
            jwt_dot_count = 2
            if clean_token.count(".") != jwt_dot_count:
                return FlextResult[FlextAuthTypes.TokenManagement.JwtTokenPayload].fail(
                    "Invalid token format"
                )

            # JWT verification using utilities
            jwt_result = FlextAuthUtilities.JWTProcessing.extract_claims(
                clean_token, config.jwt_auth_secret
            )
            if jwt_result.is_failure:
                return FlextResult[FlextAuthTypes.TokenManagement.JwtTokenPayload].fail(
                    jwt_result.error or "Token validation failed"
                )

            payload = jwt_result.value

            # Log successful validation
            logger.info(f"JWT token validated for user: {payload.get('user_id')}")

            # Build JWT payload
            exp_value = payload.get("exp", 0)
            iat_value = payload.get("iat", 0)
            jwt_payload: FlextAuthTypes.TokenManagement.JwtTokenPayload = {
                "user_id": str(payload["user_id"]),
                "exp": int(exp_value)
                if isinstance(exp_value, (int, float, str))
                else 0,
                "iat": int(iat_value)
                if isinstance(iat_value, (int, float, str))
                else 0,
                "type": "access",
                "valid": True,
            }

            # Add optional fields
            if "username" in payload:
                jwt_payload["username"] = str(payload["username"])
            if "type" in payload:
                jwt_payload["type"] = str(payload["type"])

            return FlextResult[FlextAuthTypes.TokenManagement.JwtTokenPayload].ok(
                jwt_payload
            )

    class _AuthResponseHelper(FlextHandlers):
        """Authentication response handler using FlextHandlers patterns.

        Extends FlextHandlers to provide response building with built-in
        logging, metrics tracking, and handler lifecycle management.
        """

        def __init__(self) -> None:
            """Initialize response handler."""
            config = FlextModels.CqrsConfig.Handler(
                handler_id="auth_response",
                handler_name="AuthResponseHandler",
            )
            super().__init__(config=config)

        def handle(self, data: dict[str, object]) -> FlextResult[object]:
            """Handle response building using FlextHandlers pattern.

            Args:
                data: Response data containing 'operation' and parameters

            Returns:
                FlextResult[object]: Success with response or error

            """
            operation = data.get("operation", "")

            match operation:
                case "build_auth_response":
                    auth_data = data.get("auth_data")
                    if not isinstance(auth_data, dict):
                        return FlextResult[object].fail("Invalid auth data")
                    config = data.get("config")
                    if not isinstance(config, FlextAuthConfig):
                        return FlextResult[object].fail("Invalid config")
                    return FlextResult[object].ok(
                        self.build_auth_response(auth_data, config)
                    )
                case _:
                    return FlextResult[object].fail(
                        f"Unknown response operation: {operation}"
                    )

        def build_auth_response(
            self, auth_data: dict[str, object], config: FlextAuthConfig
        ) -> FlextAuthTypes.AuthenticationResponseDict:
            """Build final authentication response with handler logging.

            Returns:
                FlextAuthTypes.AuthenticationResponseDict: Complete response

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

            log_config = FlextModels.LogOperation(
                message="Building authentication response",
                operation="build_auth_response",
                context={
                    "user_id": user.id,
                    "username": user.username,
                    "session_id": session.id,
                },
            )
            self.log_operation(log_config)

            # Create UserDict
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

            # Create SessionDict
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

            # Create authentication response
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
                    "token_type": FlextAuthConstants.Jwt.DEFAULT_TOKEN_TYPE,
                    "expires_in": config.jwt_expiry_minutes * 60,
                }

            return result_data


# Module exports
__all__ = [
    "FlextAuth",
]

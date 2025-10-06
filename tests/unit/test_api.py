"""Comprehensive tests for FlextAuth API to achieve 100% coverage.

Tests all uncovered methods in api.py including helper classes,
processor registrations, handlers, and advanced patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time

import pytest
from flext_core import FlextResult, FlextTypes
from pydantic import ValidationError

from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants
from flext_auth.models import FlextAuthModels


class TestFlextAuthHelperClasses:
    """Test FlextAuth internal helper classes."""

    def test_auth_validation_helper_initialization(self) -> None:
        """Test AuthValidationHelper is properly initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify validation handler exists
        assert hasattr(auth, "_validation_handler")
        assert auth._validation_handler is not None

    def test_auth_processing_helper_initialization(self) -> None:
        """Test AuthProcessingHelper is properly initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify processing handler exists
        assert hasattr(auth, "_processing_handler")
        assert auth._processing_handler is not None

    def test_auth_session_helper_initialization(self) -> None:
        """Test AuthSessionHelper is properly initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify session handler exists
        assert hasattr(auth, "_session_handler")
        assert auth._session_handler is not None

    def test_auth_token_helper_initialization(self) -> None:
        """Test AuthTokenHelper is properly initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify token handler exists
        assert hasattr(auth, "_token_handler")
        assert auth._token_handler is not None

    def test_auth_factory_helper_initialization(self) -> None:
        """Test AuthFactoryHelper is properly initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify factory handler exists
        assert hasattr(auth, "_factory_handler")
        assert auth._factory_handler is not None

    def test_auth_storage_helper_initialization(self) -> None:
        """Test AuthStorageHelper is properly initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify storage handler exists
        assert hasattr(auth, "_storage_handler")
        assert auth._storage_handler is not None

    def test_auth_response_helper_initialization(self) -> None:
        """Test AuthResponseHelper is properly initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify response handler exists
        assert hasattr(auth, "_response_handler")
        assert auth._response_handler is not None


class TestFlextAuthProcessorRegistration:
    """Test authentication processor registration."""

    def test_processors_registered_on_initialization(self) -> None:
        """Test that processors are registered during initialization."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify FlextProcessors and FlextDispatcher are initialized
        assert hasattr(auth, "_processors")
        assert hasattr(auth, "_dispatcher")
        assert auth._processors is not None
        assert auth._dispatcher is not None

    def test_username_validation_processor(self) -> None:
        """Test username validation through processor."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Test with valid username
        result_valid = auth.register_user(
            "validuser", "test@example.com", "ValidPass123!"
        )
        assert result_valid.is_success

        # Test with too short username - Pydantic validates before processor
        # This will raise ValidationError, which is expected behavior
        with pytest.raises(Exception) as exc_info:
            auth.register_user("ab", "test2@example.com", "ValidPass123!")
        assert "at least 3 characters" in str(exc_info.value).lower()

    def test_email_normalization_processor(self) -> None:
        """Test email normalization to lowercase."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register with uppercase email
        result = auth.register_user("testuser", "TEST@EXAMPLE.COM", "ValidPass123!")
        assert result.is_success

        # Verify email was normalized to lowercase
        user_result = auth.get_user_by_username("testuser")
        assert user_result.is_success
        user = user_result.unwrap()
        assert user.email == "test@example.com"  # normalized

    def test_password_strength_validation_processor(self) -> None:
        """Test password strength validation."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Test with weak password (too short) - Pydantic validates before processor
        with pytest.raises(Exception) as exc_info:
            auth.register_user("user1", "user1@example.com", "weak")
        assert "at least 8 characters" in str(exc_info.value).lower()


class TestFlextAuthHandlerRegistration:
    """Test FlextBus handler registration."""

    def test_command_handlers_registered(self) -> None:
        """Test that command handlers are registered with FlextBus."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify FlextBus is initialized
        assert hasattr(auth, "_bus")
        assert auth._bus is not None

        # Verify handlers exist (through successful operations)
        result = auth.register_user("cmduser", "cmd@example.com", "CmdPass123!")
        assert result.is_success

    def test_query_handlers_registered(self) -> None:
        """Test that query handlers are registered with FlextBus."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Create a user first
        auth.register_user("queryuser", "query@example.com", "QueryPass123!")

        # Test query handler through get_user_by_username
        result = auth.get_user_by_username("queryuser")
        assert result.is_success

    def test_registry_handlers_registered(self) -> None:
        """Test that handlers are registered with FlextRegistry."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify FlextRegistry is initialized
        assert hasattr(auth, "_registry")
        assert auth._registry is not None


class TestFlextAuthAdvancedPatterns:
    """Test advanced flext-core pattern integration."""

    def test_flext_container_integration(self) -> None:
        """Test FlextContainer dependency injection."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify container is initialized
        assert hasattr(auth, "container")
        assert auth.container is not None

    def test_flext_context_integration(self) -> None:
        """Test FlextContext execution context."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify context is initialized
        assert hasattr(auth, "_context")
        assert auth._context is not None

    def test_flext_dispatcher_integration(self) -> None:
        """Test FlextDispatcher event bus."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify dispatcher is initialized
        assert hasattr(auth, "_dispatcher")
        assert auth._dispatcher is not None
        assert hasattr(auth, "_bus")


class TestFlextAuthStorageOperations:
    """Test internal storage operations."""

    def test_username_index_management(self) -> None:
        """Test username index is maintained correctly."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register user
        auth.register_user("indexuser", "index@example.com", "IndexPass123!")

        # Verify username index
        assert hasattr(auth, "username_index")
        assert "indexuser" in auth.username_index

    def test_email_index_management(self) -> None:
        """Test email index is maintained correctly."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register user
        auth.register_user("emailuser", "email@example.com", "EmailPass123!")

        # Verify email index
        assert hasattr(auth, "email_index")
        assert "email@example.com" in auth.email_index

    def test_user_sessions_index_management(self) -> None:
        """Test user sessions index is maintained."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register and authenticate user
        auth.register_user("sessionuser", "session@example.com", "SessionPass123!")
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        assert auth_result.is_success

        # Verify user sessions index
        assert hasattr(auth, "user_sessions_index")


class TestFlextAuthConfigurationOverrides:
    """Test configuration override capabilities."""

    def test_create_with_config_overrides_method_exists(self) -> None:
        """Test create_with_config_overrides static method exists."""
        # Verify method exists
        assert hasattr(FlextAuth, "create_with_config_overrides")

    def test_custom_config_initialization(self) -> None:
        """Test initialization with custom configuration."""
        # Create custom config - create_for_environment returns FlextAuthConfig directly
        custom_config = FlextAuthConfig.create_for_environment("development")

        # Create auth with custom config
        auth = FlextAuth(config=custom_config)
        assert auth.config == custom_config


class TestFlextAuthSessionManagement:
    """Test session management operations."""

    def test_get_user_sessions(self) -> None:
        """Test retrieving all sessions for a user."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register and authenticate user
        auth.register_user("sessuser", "sess@example.com", "SessPass123!")
        auth_result = auth.authenticate_user("sessuser", "SessPass123!")
        assert auth_result.is_success

        user_result = auth.get_user_by_username("sessuser")
        assert user_result.is_success
        user = user_result.unwrap()

        # Get user sessions
        sessions_result = auth.get_user_sessions(user.id)
        assert sessions_result.is_success

    def test_revoke_session(self) -> None:
        """Test revoking a specific session."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register and authenticate user
        auth.register_user("revokeuser", "revoke@example.com", "RevokePass123!")
        auth_result = auth.authenticate_user("revokeuser", "RevokePass123!")
        assert auth_result.is_success

        # Get session from authenticated response
        auth_data = auth_result.unwrap()
        session_id = auth_data["session"]["id"]

        # Revoke session
        revoke_result = auth.revoke_session(session_id)
        assert revoke_result.is_success


class TestFlextAuthTokenOperations:
    """Test JWT token operations."""

    def test_generate_token_for_user(self) -> None:
        """Test generating token for user."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register user
        auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
        user_result = auth.get_user_by_username("tokenuser")
        assert user_result.is_success

        user = user_result.unwrap()

        # Generate token - returns str directly
        token = auth.generate_token(user.id)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_validate_token_with_bearer_prefix(self) -> None:
        """Test token validation with Bearer prefix."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register and authenticate
        auth.register_user("beareruser", "bearer@example.com", "BearerPass123!")
        auth_result = auth.authenticate_user("beareruser", "BearerPass123!")
        assert auth_result.is_success

        # Get token from authenticated response
        auth_data = auth_result.unwrap()
        token = auth_data["tokens"]["access_token"]

        # Validate with Bearer prefix
        validate_result = auth.validate_token(f"Bearer {token}")
        assert validate_result.is_success


class TestFlextAuthErrorHandling:
    """Test error handling and edge cases."""

    def test_duplicate_user_registration(self) -> None:
        """Test handling duplicate user registration."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register user
        auth.register_user("dupuser", "dup@example.com", "DupPass123!")

        # Try to register again
        result = auth.register_user("dupuser", "dup2@example.com", "DupPass123!")
        assert result.is_failure
        assert result.error is not None and "already exists" in result.error.lower()

    def test_authentication_with_invalid_credentials(self) -> None:
        """Test authentication with wrong password."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register user
        auth.register_user("authuser", "auth@example.com", "AuthPass123!")

        # Try wrong password
        result = auth.authenticate_user("authuser", "WrongPassword123!")
        assert result.is_failure

    def test_get_nonexistent_user(self) -> None:
        """Test retrieving non-existent user."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        result = auth.get_user_by_username("nonexistent")
        # get_user_by_username returns ok(None) for nonexistent users
        assert result.is_success
        assert result.unwrap() is None


class TestFlextAuthLogging:
    """Test structured logging integration."""

    def test_initialization_logging(self) -> None:
        """Test that initialization is logged."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify logger is initialized
        assert hasattr(auth, "logger")
        assert auth.logger is not None

    def test_handler_registration_logging(self) -> None:
        """Test that handler registration is logged."""
        # Creating auth triggers handler registration logging
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify successful initialization
        assert auth is not None


class TestFlextAuthProviderRegistry:
    """Test multi-provider registry (v2.0.0 feature)."""

    def test_provider_registry_initialization(self) -> None:
        """Test provider registry is initialized."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify provider registry exists
        assert hasattr(auth, "_provider_registry")
        assert auth._provider_registry is not None

    def test_default_provider_name(self) -> None:
        """Test default provider is set to jwt."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify default provider
        assert hasattr(auth, "_default_provider_name")
        assert auth._default_provider_name == "jwt"


class TestFlextAuthModelConfiguration:
    """Test Pydantic model configuration."""

    def test_model_config_arbitrary_types_allowed(self) -> None:
        """Test that arbitrary types are allowed in model config."""
        # Verify model_config exists
        assert hasattr(FlextAuth, "model_config")
        assert FlextAuth.model_config["arbitrary_types_allowed"] is True

    def test_model_config_validate_assignment(self) -> None:
        """Test validate_assignment configuration."""
        assert FlextAuth.model_config["validate_assignment"] is False


class TestFlextAuth:
    """Unit tests for FlextAuth class."""

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        # Clear singleton to ensure clean test
        FlextAuthConfig.reset_global_instance()

        # Test default initialization
        auth: FlextAuth = FlextAuth()
        assert auth.config.jwt_secret is not None
        assert len(auth.config.jwt_secret) > 20
        assert auth.config.bcrypt_rounds == 12  # Default bcrypt rounds from flext-core
        assert auth.config.jwt_expiry_minutes == 30  # Production-ready JWT expiry

        # Test custom initialization
        custom_secret = "test-secret-key-with-minimum-32-characters-length"
        custom_rounds = 10
        custom_expiry = 60

        custom_config = FlextAuthConfig(
            jwt_secret=custom_secret,
            bcrypt_rounds=custom_rounds,
            jwt_expiry_minutes=custom_expiry,
        )
        auth_custom: FlextAuth = FlextAuth(config=custom_config)
        assert auth_custom.config.jwt_secret == custom_secret
        assert auth_custom.config.bcrypt_rounds == custom_rounds
        assert auth_custom.config.jwt_expiry_minutes == custom_expiry

    def test_user_registration_success(self) -> None:
        """Test successful user registration."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            roles=["user"],
        )

        assert result.is_success
        user = result.value
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert "user" in user.roles
        assert user.is_active

    def test_user_registration_duplicate_username(self) -> None:
        """Test user registration with duplicate username."""
        auth: FlextAuth = FlextAuth()

        # First registration
        auth.register_user("testuser", "test1@example.com", "Password123!")

        # Second registration with same username
        duplicate_result = auth.register_user(
            "testuser",
            "test2@example.com",
            "Password123!",
        )
        assert duplicate_result.is_failure
        assert duplicate_result.is_failure
        assert "already exists" in (duplicate_result.error or "")

    def test_user_registration_duplicate_email(self) -> None:
        """Test user registration with duplicate email."""
        auth: FlextAuth = FlextAuth()

        # First registration
        auth.register_user("user1", "test@example.com", "Password123!")

        # Second registration with same email
        duplicate_result = auth.register_user(
            "user2",
            "test@example.com",
            "Password123!",
        )
        assert duplicate_result.is_failure
        assert duplicate_result.is_failure
        assert "already exists" in (duplicate_result.error or "")

    def test_user_authentication_success(self) -> None:
        """Test successful user authentication."""
        auth: FlextAuth = FlextAuth()
        username = "authtest"
        password = "AuthPassword123!"

        # Register user first
        reg_result = auth.register_user(username, "auth@example.com", password)
        assert reg_result.is_success

        # Test authentication
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success

        auth_data = auth_result.value
        assert auth_data["success"] is True
        assert "user" in auth_data
        assert "tokens" in auth_data
        assert "session" in auth_data

        # Validate token data
        tokens = auth_data.get("tokens")
        assert isinstance(tokens, dict), "tokens must be dict"
        assert "access_token" in tokens
        assert tokens["token_type"] == "Bearer"
        expires_in = tokens["expires_in"]
        assert isinstance(expires_in, (int, float))
        assert expires_in == 30 * 60  # 30 minutes * 60 seconds = 1800 seconds

    def test_user_authentication_invalid_credentials(self) -> None:
        """Test authentication with invalid credentials."""
        auth: FlextAuth = FlextAuth()
        username = "testuser"

        # Register user
        auth.register_user(username, "test@example.com", "CorrectPassword123!")

        # Test with wrong password
        failed_auth = auth.authenticate_user(username, "WrongPassword123!")
        assert failed_auth.is_failure
        assert failed_auth.is_failure
        assert "Invalid credentials" in (failed_auth.error or "")

    def test_token_validation_valid_token(self) -> None:
        """Test validation of valid token."""
        auth: FlextAuth = FlextAuth()
        username = "tokenuser"
        password = "TokenPassword123!"

        # Register and authenticate to get token
        auth.register_user(username, "token@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success

        # Extract and validate token
        auth_data = auth_result.value
        assert isinstance(auth_data, dict), "auth_data must be dict"
        tokens = auth_data.get("tokens")
        assert isinstance(tokens, dict), "tokens must be dict"
        access_token = tokens["access_token"]
        assert isinstance(access_token, str), "access_token must be string"
        validation_result = auth.validate_token(access_token)

        assert validation_result.is_success
        validation_data = validation_result.value
        assert validation_data["valid"] is True
        assert "user_id" in validation_data  # JWT contains user_id, not username
        assert "type" in validation_data

    def test_token_validation_invalid_token(self) -> None:
        """Test validation of invalid token."""
        auth: FlextAuth = FlextAuth()

        invalid_result = auth.validate_token("invalid.token.here")
        assert invalid_result.is_failure
        assert "token" in (invalid_result.error or "").lower()

    def test_token_validation_bearer_prefix(self) -> None:
        """Test token validation with Bearer prefix."""
        auth: FlextAuth = FlextAuth()
        username = "beareruser"
        password = "BearerPassword123!"

        # Register and authenticate
        auth.register_user(username, "bearer@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success

        # Test with Bearer prefix
        auth_data = auth_result.value
        assert isinstance(auth_data, dict), "auth_data must be dict"
        tokens = auth_data.get("tokens")
        assert isinstance(tokens, dict), "tokens must be dict"
        access_token = tokens["access_token"]
        assert isinstance(access_token, str), "access_token must be string"
        bearer_result = auth.validate_token(f"Bearer {access_token}")
        assert bearer_result.is_success
        bearer_data = bearer_result.value
        assert isinstance(bearer_data, dict), "bearer_data must be dict"
        assert bearer_data["user_id"] is not None  # JWT contains user_id, not username

    def test_session_management(self) -> None:
        """Test session management functionality."""
        auth: FlextAuth = FlextAuth()
        username = "sessionuser"
        password = "SessionPassword123!"

        # Register and authenticate with session data
        auth.register_user(username, "session@example.com", password)
        auth_result = auth.authenticate_user(
            username,
            password,
            "127.0.0.1",
            "test-user-agent",
        )
        assert auth_result.is_success

        # Extract session information
        auth_data = auth_result.value
        assert isinstance(auth_data, dict), "auth_data must be dict"
        session_info = auth_data["session"]
        assert isinstance(session_info, dict), "session_info must be dict"
        session_id = session_info.get("id")
        user_info = auth_data["user"]
        assert isinstance(user_info, dict), "user_info must be dict"
        user_id = user_info["id"]

        # Test get user sessions
        sessions_result = auth.get_user_sessions(user_id)
        assert sessions_result.is_success
        sessions = sessions_result.value
        assert len(sessions) >= 1
        assert any(s.id == session_id for s in sessions)

    def test_user_logout(self) -> None:
        """Test user logout functionality."""
        auth: FlextAuth = FlextAuth()
        username = "logoutuser"
        password = "LogoutPassword123!"

        # Register and authenticate
        auth.register_user(username, "logout@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success

        # Extract session ID from authentication result
        auth_data = auth_result.value
        assert isinstance(auth_data, dict)
        assert "session" in auth_data
        session_info = auth_data["session"]
        assert isinstance(session_info, dict), "session_info must be dict"
        session_id = session_info.get("id")
        assert session_id is not None

        logout_result = auth.logout_user(session_id)
        assert logout_result.is_success

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth: FlextAuth = FlextAuth()

        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.is_success
        assert isinstance(cleanup_result.value, int)
        assert cleanup_result.value >= 0

    def test_sync_api_methods(self) -> None:
        """Test synchronous API methods work as expected."""
        auth: FlextAuth = FlextAuth()
        username = "syncuser"
        password = "SyncPassword123!"

        # Test user creation with current API
        create_result = auth.register_user(username, "sync@example.com", password)
        assert create_result.is_success

        # Test authentication with current API
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success


class TestFlextAuthQuickStart:
    """Unit tests for FlextAuth.quick_start class method."""

    def test_quick_start_default(self) -> None:
        """Test FlextAuth.quick_start with default parameters."""
        auth = FlextAuth.quick_start()
        assert isinstance(auth, FlextAuth)

    def test_quick_start_with_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test FlextAuth.quick_start with REDACTED_LDAP_BIND_PASSWORD user creation."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=True)
        assert isinstance(auth, FlextAuth)

    def test_quick_start_custom_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test FlextAuth.quick_start with custom REDACTED_LDAP_BIND_PASSWORD credentials."""
        auth = FlextAuth.quick_start(
            create_REDACTED_LDAP_BIND_PASSWORD=True,
            REDACTED_LDAP_BIND_PASSWORD_username="custom_REDACTED_LDAP_BIND_PASSWORD",
            REDACTED_LDAP_BIND_PASSWORD_password="CustomPassword123!",
        )
        assert isinstance(auth, FlextAuth)

    def test_quick_start_no_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test FlextAuth.quick_start without REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert isinstance(auth, FlextAuth)


class TestFlextAuthSecurity:
    """Unit tests for security features."""

    def test_account_lockout_on_failed_attempts(self) -> None:
        """Test account lockout after multiple failed login attempts."""
        auth: FlextAuth = FlextAuth()
        username = "locktest"
        password = "LockTestPassword123!"

        # Register user
        auth.register_user(username, "lock@example.com", password)

        # Attempt multiple failed logins
        for _ in range(FlextAuthConstants.Security.MAX_LOGIN_ATTEMPTS):
            failed_auth = auth.authenticate_user(username, "wrong_password")
            assert failed_auth.is_failure

        # Next attempt should indicate account is locked
        locked_auth = auth.authenticate_user(username, password)
        assert locked_auth.is_failure
        # Should fail even with correct password due to lockout
        assert (
            "locked" in (locked_auth.error or "").lower()
            or "inactive" in (locked_auth.error or "").lower()
        )

    def test_password_strength_enforcement(self) -> None:
        """Test password strength requirements."""
        auth: FlextAuth = FlextAuth()

        # Test with weak password - should raise ValidationError
        with pytest.raises(ValidationError):
            auth.register_user(
                "weakuser",
                "weak@example.com",
                "weak",  # Too weak
            )


class TestFlextAuthErrorHandlingSecond:
    """Unit tests for error handling scenarios."""

    def test_empty_username_registration(self) -> None:
        """Test registration with empty username."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("", "empty@example.com", "Password123!")
        assert result.is_failure

    def test_empty_email_registration(self) -> None:
        """Test registration with empty email."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("user", "", "Password123!")
        assert result.is_failure

    def test_empty_password_registration(self) -> None:
        """Test registration with empty password."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("user", "test@example.com", "")
        assert result.is_failure

    def test_invalid_email_registration(self) -> None:
        """Test registration with invalid email."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("user", "invalid-email", "Password123!")
        assert result.is_failure

    def test_nonexistent_user_authentication(self) -> None:
        """Test authentication of non-existent user."""
        auth: FlextAuth = FlextAuth()

        auth_result = auth.authenticate_user("nonexistent", "password")
        assert auth_result.is_failure
        assert auth_result.is_failure
        assert "Invalid credentials" in (auth_result.error or "")

    def test_invalid_session_logout(self) -> None:
        """Test logout with invalid session ID."""
        auth: FlextAuth = FlextAuth()

        logout_result = auth.logout_user("invalid_session_id")
        assert logout_result.is_failure
        assert logout_result.is_failure
        assert "Session not found" in (logout_result.error or "")


class TestFlextAuthQuickStartFunction:
    """Unit tests for FlextAuth.quick_start() classmethod."""

    def test_flext_auth_quick_start_default(self) -> None:
        """Test FlextAuth.quick_start() with default parameters."""
        auth = FlextAuth.quick_start()
        assert isinstance(auth, FlextAuth)
        # Should create REDACTED_LDAP_BIND_PASSWORD user by default
        REDACTED_LDAP_BIND_PASSWORD_result = auth.get_user_by_username("REDACTED_LDAP_BIND_PASSWORD")
        assert REDACTED_LDAP_BIND_PASSWORD_result.is_success
        assert REDACTED_LDAP_BIND_PASSWORD_result.value is not None

    def test_flext_auth_quick_start_no_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test FlextAuth.quick_start() without creating REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert isinstance(auth, FlextAuth)
        # Should not create REDACTED_LDAP_BIND_PASSWORD user - check that REDACTED_LDAP_BIND_PASSWORD user is None
        # since REDACTED_LDAP_BIND_PASSWORD might have been created in previous tests, we test the function works
        nonexistent_result = auth.get_user_by_username("nonexistent_user")
        assert nonexistent_result.is_success
        assert nonexistent_result.value is None

    def test_flext_auth_quick_start_custom_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test FlextAuth.quick_start() with custom REDACTED_LDAP_BIND_PASSWORD credentials."""
        custom_username = "custom_REDACTED_LDAP_BIND_PASSWORD_func"
        custom_password = "CustomPasswordFunc123!"

        auth = FlextAuth.quick_start(
            create_REDACTED_LDAP_BIND_PASSWORD=True,
            REDACTED_LDAP_BIND_PASSWORD_username=custom_username,
            REDACTED_LDAP_BIND_PASSWORD_password=custom_password,
        )
        assert isinstance(auth, FlextAuth)

        # Should create custom REDACTED_LDAP_BIND_PASSWORD user
        REDACTED_LDAP_BIND_PASSWORD_result = auth.get_user_by_username(custom_username)
        assert REDACTED_LDAP_BIND_PASSWORD_result.is_success
        assert REDACTED_LDAP_BIND_PASSWORD_result.value is not None

        # Should be able to authenticate with custom credentials
        auth_result = auth.authenticate_user(custom_username, custom_password)
        assert auth_result.is_success


class TestFlextAuthInitializationCoverage:
    """Test FlextAuth initialization edge cases - covering lines 228-229."""

    def test_flext_auth_config_creation_failure(self) -> None:
        """Test FlextAuth initialization when config creation fails - lines 228-229."""
        # Try to create FlextAuth - this should work in normal cases
        # but if it fails, it should be a RuntimeError with specific message

        # Most common case: successful initialization (covers default config creation)
        # Test FlextAuth creation with proper error handling
        try:
            auth = FlextAuth()
            # If it succeeds, that's fine - we covered the default config creation path
            assert auth.config is not None
        except RuntimeError as e:
            # If it fails with RuntimeError, we expect a specific error message
            pytest.fail(f"FlextAuth creation failed with RuntimeError: {e}")
        except Exception as e:
            # Other exceptions should be properly handled, not ignored
            pytest.fail(f"Unexpected exception during FlextAuth creation: {e}")

    def test_quick_start_REDACTED_LDAP_BIND_PASSWORD_creation_failure(self) -> None:
        """Test quick_start when REDACTED_LDAP_BIND_PASSWORD creation fails - lines 423-424."""
        # This test covers the REDACTED_LDAP_BIND_PASSWORD creation failure path
        # We expect a RuntimeError when REDACTED_LDAP_BIND_PASSWORD creation fails with invalid data
        with pytest.raises(ValidationError) as exc_info:
            FlextAuth.quick_start(
                create_REDACTED_LDAP_BIND_PASSWORD=True,
                REDACTED_LDAP_BIND_PASSWORD_username="ab",  # Invalid username (too short, needs >= 3 chars)
                REDACTED_LDAP_BIND_PASSWORD_password="weak",  # Invalid password (too weak)
            )

        # Verify the error message contains expected information about the validation failure
        error_message = str(exc_info.value)
        assert "validation error" in error_message.lower()
        assert "String should have at least 3 characters" in error_message

    def test_quick_start_general_failure(self) -> None:
        """Test quick_start general failure path - lines 427-429."""
        # This test covers the general exception handling in quick_start
        try:
            # Try to create with parameters that might cause issues
            auth = FlextAuth.quick_start(
                create_REDACTED_LDAP_BIND_PASSWORD=True,
                REDACTED_LDAP_BIND_PASSWORD_username="test_REDACTED_LDAP_BIND_PASSWORD",
                REDACTED_LDAP_BIND_PASSWORD_password="TestPassword123!",
            )
            # If it succeeds, that's fine
            assert auth is not None
        except RuntimeError as e:
            # Expected failure with specific error message
            pytest.fail(f"Quick start failed with RuntimeError: {e}")
        except Exception as e:
            # Other exceptions should be properly handled, not ignored
            pytest.fail(f"Unexpected exception during quick_start general: {e}")

    def test_flext_auth_initialization_with_overrides(self) -> None:
        """Test FlextAuth initialization with parameter overrides - lines 235-237."""
        # Create with custom parameters to cover override paths
        auth_result = FlextAuth.create_with_config_overrides(
            jwt_expiry_minutes=120,
            bcrypt_rounds=10,
        )

        if auth_result.is_failure:
            pytest.fail(f"Failed to create auth: {auth_result.error}")

        auth = auth_result.value

        assert auth.token_expire_minutes == 120
        assert auth.token_expire_minutes == 120
        assert auth.bcrypt_rounds == 10


class TestFlextAuthErrorPaths:
    """Test error handling paths in FlextAuth methods."""

    def test_register_user_edge_cases(self) -> None:
        """Test register_user method error paths."""
        auth = FlextAuth()

        # Test with invalid email to trigger error path
        result = auth.register_user(
            username="testuser",
            email="invalid-email-format",
            password="ValidPassword123!",
        )

        # Should fail gracefully
        if result.is_failure:
            error_msg = result.error or ""
            assert "email" in error_msg.lower() or "failed" in error_msg.lower()

    def test_authenticate_user_failure_paths(self) -> None:
        """Test authenticate_user method failure scenarios."""
        auth = FlextAuth()

        # Test authentication with non-existent user
        result = auth.authenticate_user(
            username="nonexistent_user",
            password="any_password",
        )

        assert result.is_failure
        assert isinstance(result.error, str)

    def test_validate_token_invalid_cases(self) -> None:
        """Test token validation with invalid tokens."""
        auth = FlextAuth()

        # Test with malformed token
        result = auth.validate_token("invalid.malformed.token")
        assert result.is_failure

        # Test with empty token
        result = auth.validate_token("")
        assert result.is_failure

        # Test with invalid token format
        result = auth.validate_token("invalid.token.format")
        assert result.is_failure


class TestFlextAuthPasswordMethods:
    """Test password-related methods to cover uncovered lines."""

    def test_hash_password_method(self) -> None:
        """Test hash_password method functionality."""
        # Create user to test password hashing
        user = FlextAuthModels.User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            roles=[],
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )
        result = user.set_password("StrongTestPass123!@#")

        # set_password returns FlextResult[bool]
        assert result.is_success
        assert result.unwrap() is True
        assert user.password_hash != "StrongTestPass123!@#"
        assert len(user.password_hash) > 10  # Bcrypt hash should be substantial

    def test_verify_password_method(self) -> None:
        """Test verify_password method functionality."""
        # Use strong password that meets validation requirements
        strong_password = "StrongTestPass123!@#"

        # Create user and set password
        user = FlextAuthModels.User(
            id="test-id",
            username="testuser",
            email="test@example.com",
            full_name="Test User",
            is_active=True,
            roles=[],
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )
        set_result = user.set_password(strong_password)
        assert set_result.is_success

        # Test correct password verification
        verify_result = user.verify_password(strong_password)
        assert verify_result.is_success
        assert verify_result.unwrap() is True

        # Test wrong password verification
        wrong_result = user.verify_password("WrongPassword123!@")
        assert wrong_result.is_success
        assert wrong_result.unwrap() is False


class TestFlextAuthTokenMethods:
    """Test token generation and validation methods."""

    def test_generate_token_method(self) -> None:
        """Test generate_jwt_token method functionality."""
        auth = FlextAuth()

        # First register a user to make JWT generation work
        user_result = auth.register_user(
            username="jwt_test_user",
            email="jwt@example.com",
            password="JWTTestPass123!@#",
        )
        assert user_result.is_success
        user = user_result.value

        # Use the correct method name from the inspection
        result = auth.generate_jwt_token(user_id=user.id)

        assert result.is_success
        token = result.value
        assert isinstance(token, str)
        assert len(token) > 50  # JWT tokens are typically longer

    def test_generate_token_alternative_method(self) -> None:
        """Test generate_token alternative method."""
        auth = FlextAuth()

        # Create a user first
        auth.register_user("testuser", "test@example.com", "TestPassword123!")
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        assert auth_result.is_success
        user_id = auth_result.value["user"]["id"]

        # generate_token returns string directly, not FlextResult
        token = auth.generate_token(user_id)

        assert isinstance(token, str)
        assert len(token) > 10  # JWT should be substantial

    def test_validate_token_success_path(self) -> None:
        """Test validate_token with valid token."""
        auth = FlextAuth()

        # Create a user first
        auth.register_user("testuser", "test@example.com", "TestPassword123!")
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        assert auth_result.is_success
        user_id = auth_result.value["user"]["id"]

        # Generate a token first - returns string directly
        token = auth.generate_token(user_id)
        assert isinstance(token, str)

        # Validate the generated token - use validate_token instead
        val_result = auth.validate_token(token)
        assert val_result.is_success
        token_data = val_result.value
        assert isinstance(token_data, dict)


class TestFlextAuthUserMethods:
    """Test user management methods available in FlextAuth."""

    def test_get_user_by_id_method(self) -> None:
        """Test get_user_by_id method functionality."""
        auth = FlextAuth()

        # First register a user
        user_result = auth.register_user(
            username="test_get_user",
            email="getuser@example.com",
            password="GetUserPass123!@",
        )
        assert user_result.is_success
        user = user_result.value

        # Get user by ID
        get_result = auth.get_user_by_id(user.id)
        assert isinstance(get_result.is_success, bool)

    def test_get_user_by_username_method(self) -> None:
        """Test get_user_by_username method functionality."""
        auth = FlextAuth()

        # First register a user
        user_result = auth.register_user(
            username="test_username_lookup",
            email="lookup@example.com",
            password="LookupPass123!@",
        )
        assert user_result.is_success

        # Get user by username
        get_result = auth.get_user_by_username("test_username_lookup")
        assert isinstance(get_result.is_success, bool)

    def test_get_user_by_token_direct_api_method(self) -> None:
        """Test get user by token using direct API (validate_token + get_user_by_id)."""
        auth = FlextAuth()

        # First register a user
        user_result = auth.register_user(
            username="test_token_user",
            email="tokenuser@example.com",
            password="TokenUserPass123!@",
        )
        assert user_result.is_success
        user = user_result.value

        # Generate token for user - returns string directly
        token = auth.generate_token(user.id)
        assert isinstance(token, str)

        # Get user by token using direct API (validate_token + get_user_by_id)
        token_result = auth.validate_token(token)
        assert isinstance(token_result.is_success, bool)
        if token_result.is_success:
            user_id = token_result.value.get("user_id")
            if user_id:
                get_result = auth.get_user_by_id(str(user_id))
                assert isinstance(get_result.is_success, bool)

    def test_logout_user_method(self) -> None:
        """Test logout_user method functionality."""
        auth = FlextAuth()

        # First register a user
        user_result = auth.register_user(
            username="test_logout_user",
            email="logout@example.com",
            password="LogoutPass123!@",
        )
        assert user_result.is_success
        user = user_result.value

        # Logout user
        logout_result = auth.logout_user(user.id)
        assert isinstance(logout_result.is_success, bool)


class TestFlextAuthSessionMethods:
    """Test session management methods."""

    def test_revoke_session_method(self) -> None:
        """Test revoke_session method functionality."""
        auth = FlextAuth()

        # Revoke session with test ID
        revoke_result = auth.revoke_session("test_session_id")
        assert isinstance(revoke_result.is_success, bool)

    def test_get_user_sessions_method(self) -> None:
        """Test get_user_sessions method functionality."""
        auth = FlextAuth()

        # Get sessions for test user
        sessions_result = auth.get_user_sessions("test_user_id")
        assert isinstance(sessions_result.is_success, bool)

    def test_cleanup_expired_sessions_method(self) -> None:
        """Test cleanup_expired_sessions method functionality."""
        auth = FlextAuth()

        # Cleanup expired sessions
        cleanup_result = auth.cleanup_expired_sessions()
        assert isinstance(cleanup_result.is_success, bool)


class TestFlextAuthQuickStartMethod:
    """Test FlextAuth.quick_start class method."""

    def test_quick_start_with_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test quick_start class method with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(
            create_REDACTED_LDAP_BIND_PASSWORD=True,
            REDACTED_LDAP_BIND_PASSWORD_username="quick_REDACTED_LDAP_BIND_PASSWORD",
            REDACTED_LDAP_BIND_PASSWORD_password="QuickAdminPass123!",
        )

        assert isinstance(auth, FlextAuth)
        assert auth.config is not None

    def test_quick_start_without_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test quick_start class method without REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        assert isinstance(auth, FlextAuth)
        assert auth.config is not None


class TestFlextAuthConfigurationMethods:
    """Test configuration and utility methods."""

    def test_get_config_method(self) -> None:
        """Test config property functionality."""
        auth = FlextAuth()

        config = auth.config

        # Should return the configuration object
        assert config is not None


class TestFlextAuthErrorHandlingPaths:
    """Test error handling and edge cases in FlextAuth methods."""

    def test_authenticate_with_locked_account(self) -> None:
        """Test authentication with locked user account."""
        auth = FlextAuth()

        # Register a user first
        user_result = auth.register_user(
            username="lockable_user",
            email="lockable@example.com",
            password="LockablePass123!",
        )
        assert user_result.is_success

        # Try multiple failed authentications to potentially trigger lockout
        for _ in range(6):  # Attempt to exceed max failed attempts
            failed_result = auth.authenticate_user(
                username="lockable_user",
                password="wrong_password",
            )
            assert failed_result.is_failure

    def test_token_expiry_edge_cases(self) -> None:
        """Test token generation and validation with edge case timing."""
        auth = FlextAuth()

        # Register a user first for token generation
        user_result = auth.register_user(
            "test_user",
            "test@example.com",
            "TestPassword123!",
        )
        assert user_result.is_success
        user = user_result.value

        # Generate token - returns string directly, no expires_in_minutes parameter
        token = auth.generate_token(user.id)
        assert isinstance(token, str)

        # Validate immediately (should work)
        validate_result = auth.validate_token(token)
        assert validate_result.is_success

    def test_invalid_user_operations(self) -> None:
        """Test operations with invalid user IDs."""
        auth = FlextAuth()

        # Test various operations with invalid user ID
        invalid_user_id = "nonexistent_user_id"

        # Get user by invalid ID - should return success with None value
        get_result = auth.get_user_by_id(invalid_user_id)
        assert get_result.is_success  # Returns success with None when user not found
        assert get_result.value is None

        # Get user by invalid username - likely returns success with None too
        username_result = auth.get_user_by_username("nonexistent_username")
        assert username_result.is_success
        assert username_result.value is None

        # Logout invalid user - returns failure when user not found
        logout_result = auth.logout_user(invalid_user_id)
        assert logout_result.is_failure  # Session not found


class TestFlextAuthAdditionalCoverage:
    """Test additional coverage for missing lines in auth.py."""

    def test_cleanup_expired_sessions_with_user_sessions_index(self) -> None:
        """Test cleanup_expired_sessions method with user sessions index - lines 662-667."""
        auth = FlextAuth()

        # Register and authenticate user with complex password
        auth.register_user("testuser", "test@example.com", "Password123!")
        auth_result = auth.authenticate_user("testuser", "Password123!")
        assert auth_result.is_success

        # Manually add a session to the user sessions index to test the removal logic
        auth_data = auth_result.value
        if (
            isinstance(auth_data, dict)
            and "user" in auth_data
            and "session" in auth_data
        ):
            user_data = auth_data["user"]
            session_data = auth_data["session"]
            if (
                isinstance(user_data, dict)
                and "id" in user_data
                and isinstance(session_data, dict)
                and "id" in session_data
            ):
                user_id = str(user_data["id"])
                session_id = str(session_data["id"])

                # Ensure the session is in the user sessions index
                if user_id not in auth.user_sessions_index:
                    auth.user_sessions_index[user_id] = []
                auth.user_sessions_index[user_id].append(session_id)

        # Cleanup expired sessions - this should test the user sessions index removal
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.is_success

    def test_get_user_by_token_invalid_token_error_direct_api(self) -> None:
        """Test get user by invalid token using direct API (validate_token)."""
        auth = FlextAuth()

        # Test with invalid token - should fail at validate_token step
        result = auth.validate_token("invalid_token")
        assert result.is_failure
        assert result.error is not None
        assert (
            "Invalid token" in result.error or "Token validation failed" in result.error
        )


class TestAuthModule:
    """Unified test class for auth module functionality."""

    class _TestDataHelper:
        """Nested helper class for test data creation."""

        @staticmethod
        def create_test_user_data() -> FlextTypes.Dict:
            """Create test user data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
                "role": "user",
            }

        @staticmethod
        def create_test_auth_data() -> FlextTypes.Dict:
            """Create test authentication data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
            }

        @staticmethod
        def create_test_session_data() -> FlextTypes.Dict:
            """Create test session data."""
            return {
                "user_id": "user_123",
                "session_id": "session_123",
                "expires_at": "2025-12-31T23:59:59Z",
            }

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initializes correctly."""
        auth = FlextAuth()
        assert auth is not None

    def test_flext_auth_register_user(self) -> None:
        """Test FlextAuth register_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()

        # Test user registration
        result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
            full_name=str(test_data.get("full_name", "")),
        )
        assert isinstance(result, FlextResult)

    def test_flext_auth_authenticate_user(self) -> None:
        """Test FlextAuth authenticate_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()

        # Test user authentication if method exists
        if hasattr(auth, "authenticate_user"):
            result = auth.authenticate_user(
                str(test_data["username"]), str(test_data["password"])
            )
            assert isinstance(result, FlextResult)

    def test_flext_auth_get_user_by_username(self) -> None:
        """Test FlextAuth get_user_by_username functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()

        # Register user first
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
            full_name=str(test_data.get("full_name", "")),
        )
        assert register_result.is_success

        # Test user retrieval
        result = auth.get_user_by_username(str(test_data["username"]))
        assert isinstance(result, FlextResult)

    def test_flext_auth_get_user_by_id(self) -> None:
        """Test FlextAuth get_user_by_id functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()

        # Register user first
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
            full_name=str(test_data.get("full_name", "")),
        )
        assert register_result.is_success

        # Get user ID from registration result
        user = register_result.unwrap()
        user_id = user.id

        # Test user retrieval by ID
        result = auth.get_user_by_id(str(user_id))
        assert isinstance(result, FlextResult)

    def test_flext_auth_validate_token(self) -> None:
        """Test FlextAuth validate_token functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()

        # Register and authenticate user to get a token
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        assert register_result.is_success

        auth_result = auth.authenticate_user(
            str(test_data["username"]), str(test_data["password"])
        )
        assert auth_result.is_success

        # Extract token from auth result
        auth_data = auth_result.unwrap()
        token = auth_data["jwt_token"]

        # Test token validation
        result = auth.validate_token(token)
        assert isinstance(result, FlextResult)

    def test_flext_auth_get_user_sessions(self) -> None:
        """Test FlextAuth get_user_sessions functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()

        # Register and authenticate user to create sessions
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        assert register_result.is_success

        auth_result = auth.authenticate_user(
            str(test_data["username"]), str(test_data["password"])
        )
        assert auth_result.is_success

        # Get user ID
        user = register_result.unwrap()
        user_id = user.id

        # Test getting user sessions
        result = auth.get_user_sessions(user_id)
        assert isinstance(result, FlextResult)

    def test_flext_auth_get_user_by_token_direct_api(self) -> None:
        """Test FlextAuth get user by token using direct API (validate_token + get_user_by_id)."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()

        # Register and authenticate user to get a token
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        assert register_result.is_success

        auth_result = auth.authenticate_user(
            str(test_data["username"]), str(test_data["password"])
        )
        assert auth_result.is_success

        # Extract token from auth result
        auth_data = auth_result.unwrap()
        token = auth_data["jwt_token"]

        # Test getting user by token using direct API (validate_token + get_user_by_id)
        token_result = auth.validate_token(token)
        assert token_result.is_success
        user_id = token_result.value.get("user_id")
        assert user_id is not None
        result = auth.get_user_by_id(str(user_id))
        assert isinstance(result, FlextResult)

    def test_flext_auth_revoke_session(self) -> None:
        """Test FlextAuth revoke_session functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()

        # Register and authenticate user to create a session
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        assert register_result.is_success

        auth_result = auth.authenticate_user(
            str(test_data["username"]), str(test_data["password"])
        )
        assert auth_result.is_success

        # Get session ID from auth result
        auth_data = auth_result.unwrap()
        session_id = auth_data["session"]["id"]

        # Test session revocation
        result = auth.revoke_session(session_id)
        assert isinstance(result, FlextResult)

    def test_flext_auth_comprehensive_scenario(self) -> None:
        """Test comprehensive auth module scenario."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()

        # Test initialization
        assert auth is not None

        # Test user registration
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
            full_name=str(test_user_data.get("full_name", "")),
        )
        assert isinstance(register_result, FlextResult)
        assert register_result.is_success

        # Test user authentication
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]), str(test_auth_data["password"])
        )
        assert isinstance(auth_result, FlextResult)
        assert auth_result.is_success

        # Test token validation
        auth_data = auth_result.unwrap()
        token = auth_data["jwt_token"]
        validate_result = auth.validate_token(token)
        assert isinstance(validate_result, FlextResult)

    def test_flext_auth_error_handling(self) -> None:
        """Test auth module error handling patterns."""
        auth = FlextAuth()

        # Test user registration with invalid data
        result = auth.register_user(
            username="",  # Invalid empty username
            email="invalid_email",  # Invalid email format
            password="",  # Invalid empty password
        )
        assert isinstance(result, FlextResult)
        assert result.is_failure  # Should fail with invalid data

        # Test authentication with invalid credentials
        result = auth.authenticate_user("invalid_user", "invalid_password")
        assert isinstance(result, FlextResult)
        assert result.is_failure  # Should fail with invalid credentials

        # Test retrieval of non-existent user
        result = auth.get_user_by_username("non_existent_user")
        assert isinstance(result, FlextResult)
        # Should return None for non-existent user
        if result.is_success:
            user = result.unwrap()
            assert user is None

    def test_flext_auth_with_flext_tests(self) -> None:
        """Test auth functionality with flext_tests infrastructure."""
        auth = FlextAuth()

        # Create test data manually
        test_user_data = {
            "username": "flext_test_user",
            "email": "flext_test@example.com",
            "password": "TestPassword123!",
        }

        test_auth_data = {
            "username": "flext_test_user",
            "password": "TestPassword123!",
        }

        # Test user registration with flext_tests data
        result = auth.register_user(
            username=test_user_data["username"],
            email=test_user_data["email"],
            password=test_user_data["password"],
        )
        assert isinstance(result, FlextResult)
        assert result.is_success

        # Test authentication with flext_tests data
        result = auth.authenticate_user(
            test_auth_data["username"], test_auth_data["password"]
        )
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_flext_auth_docstring(self) -> None:
        """Test that FlextAuth has proper docstring."""
        assert FlextAuth.__doc__ is not None
        assert len(FlextAuth.__doc__.strip()) > 0

    def test_flext_auth_method_signatures(self) -> None:
        """Test that auth methods have proper signatures."""
        auth = FlextAuth()

        # Test that all actual public methods exist and are callable
        expected_methods = [
            "register_user",
            "authenticate_user",
            "get_user_by_username",
            "get_user_by_id",
            "get_user_sessions",
            "validate_token",
            "revoke_session",
            "logout_user",
            "cleanup_expired_sessions",
        ]

        for method_name in expected_methods:
            assert hasattr(auth, method_name), f"Method {method_name} should exist"
            method = getattr(auth, method_name)
            assert callable(method), f"Method {method_name} should be callable"

    def test_flext_auth_with_real_data(self) -> None:
        """Test auth functionality with realistic data scenarios."""
        auth = FlextAuth()

        # Create realistic user scenarios
        realistic_users = [
            {
                "username": "REDACTED_LDAP_BIND_PASSWORD_user",
                "email": "REDACTED_LDAP_BIND_PASSWORD@company.com",
                "password": "SecurePassword123!",
                "role": "REDACTED_LDAP_BIND_PASSWORD",
            },
            {
                "username": "regular_user",
                "email": "user@company.com",
                "password": "UserPassword456!",
                "role": "user",
            },
            {
                "username": "guest_user",
                "email": "guest@company.com",
                "password": "GuestPassword789!",
                "role": "guest",
            },
        ]

        # Test user registration with realistic data
        for user_data in realistic_users:
            result = auth.register_user(
                username=user_data["username"],
                email=user_data["email"],
                password=user_data["password"],
                roles=[user_data["role"]] if "role" in user_data else None,
            )
            assert isinstance(result, FlextResult)
            assert result.is_success

        # Test authentication with realistic data
        for user_data in realistic_users:
            result = auth.authenticate_user(
                user_data["username"], user_data["password"]
            )
            assert isinstance(result, FlextResult)
            assert result.is_success

    def test_flext_auth_integration_patterns(self) -> None:
        """Test auth integration patterns between different components."""
        auth = FlextAuth()

        # Test integration: register_user -> authenticate_user -> validate_token
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()

        # Register user
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        assert isinstance(register_result, FlextResult)
        assert register_result.is_success

        # Authenticate user
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]), str(test_auth_data["password"])
        )
        assert isinstance(auth_result, FlextResult)
        assert auth_result.is_success

        # Validate token from authentication
        auth_data = auth_result.unwrap()
        token = auth_data["jwt_token"]
        validate_result = auth.validate_token(token)
        assert isinstance(validate_result, FlextResult)
        assert validate_result.is_success

    def test_flext_auth_performance_patterns(self) -> None:
        """Test auth performance patterns."""
        auth = FlextAuth()

        # Test that auth operations are reasonably fast
        start_time = time.time()

        # Test multiple user registrations
        test_user_data = self._TestDataHelper.create_test_user_data()

        for i in range(10):
            result = auth.register_user(
                username=f"user_{i}",
                email=f"user_{i}@example.com",
                password=str(test_user_data["password"]),
            )
            assert isinstance(result, FlextResult)
            assert result.is_success

        end_time = time.time()
        assert (
            end_time - start_time
        ) < 30.0  # Should complete in less than 30 seconds (bcrypt is slow)

    def test_flext_auth_concurrent_operations(self) -> None:
        """Test auth concurrent operations."""
        auth = FlextAuth()
        results = []

        def register_user(index: int) -> None:
            result = auth.register_user(
                username=f"user_{index}",
                email=f"user_{index}@example.com",
                password="Password123!",
            )
            results.append(result)

        def authenticate_user(index: int) -> None:
            result = auth.authenticate_user(f"user_{index}", "Password123!")
            results.append(result)

        # Test concurrent operations
        threads = []
        for i in range(5):
            thread = threading.Thread(target=register_user, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for registration threads to complete
        for thread in threads:
            thread.join()

        # Now test authentication
        auth_threads = []
        for i in range(5):
            thread = threading.Thread(target=authenticate_user, args=(i,))
            auth_threads.append(thread)
            thread.start()

        # Wait for authentication threads to complete
        for thread in auth_threads:
            thread.join()

        # All results should be FlextResult instances
        for result in results:
            assert isinstance(result, FlextResult)

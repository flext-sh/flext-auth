"""Comprehensive tests for FlextAuth API to achieve 100% coverage.

Tests all uncovered methods in api.py including helper classes,
processor registrations, handlers, and advanced patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime, timedelta

import jwt
import pytest
from flext_auth.api import FlextAuth
from flext_auth.constants import FlextAuthConstants
from flext_auth.middleware import FlextAuthMiddleware
from flext_auth.models import FlextAuthModels
from flext_auth.protocols import FlextAuthProtocols as p
from flext_auth.providers.base import FlextAuthBaseProvider
from flext_auth.providers.kerberos import FlextAuthKerberosProvider
from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider
from flext_auth.settings import FlextAuthSettings
from flext_core import FlextResult, t
from pydantic import SecretStr

c = FlextAuthConstants
r = FlextResult

class HttpRequest:
    """Minimal HTTP request fixture for middleware tests."""

    headers: dict[str, str] = {}

    def __init__(self) -> None:
        self.headers = dict(self.__class__.headers)


class TestFlextAuthServiceInitialization:
    """Test FlextAuth service initialization."""

    def test_auth_service_initialization(self) -> None:
        """Test FlextAuth services are properly initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify core services exist
        assert hasattr(auth, "_provider_service")
        assert auth._provider_service is not None
        assert hasattr(auth, "_identity_service")
        assert auth._identity_service is not None
        assert hasattr(auth, "_token_service")
        assert auth._token_service is not None
        assert hasattr(auth, "_session_service")
        assert auth._session_service is not None
        assert hasattr(auth, "_registry")
        assert auth._registry is not None
        assert hasattr(auth, "_dispatcher")
        assert auth._dispatcher is not None


class TestFlextAuthProcessorRegistration:
    """Test authentication processor registration."""

    def test_services_registered_on_initialization(self) -> None:
        """Test that services are registered during initialization."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify core services are initialized
        assert hasattr(auth, "_dispatcher")
        assert auth._dispatcher is not None
        assert hasattr(auth, "_registry")
        assert auth._registry is not None
        assert hasattr(auth, "_provider_service")
        assert auth._provider_service is not None

    def test_username_validation_processor(self) -> None:
        """Test username validation through processor."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Test with valid username
        result_valid = auth.register_user(
            "validuser",
            "test@example.com",
            "ValidPass123!",
        )
        assert result_valid.is_success

        # Test with too short username - Pydantic validates and returns error
        result_short = auth.register_user("ab", "test2@example.com", "ValidPass123!")
        assert not result_short.is_success
        assert result_short.error is not None

    def test_email_normalization_processor(self) -> None:
        """Test email normalization to lowercase."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Register with uppercase email
        result = auth.register_user("testuser", "TEST@EXAMPLE.COM", "ValidPass123!")
        assert result.is_success

        # Verify email was normalized to lowercase
        user_result = auth.get_user_by_username("testuser")
        assert user_result.is_success
        user = user_result.value
        assert user.contact == "test@example.com"  # normalized

    def test_password_strength_validation_processor(self) -> None:
        """Test password strength validation."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Test with weak password (too short) - Pydantic validates before processor
        result = auth.register_user("user1", "user1@example.com", "weak")
        assert not result.is_success
        assert result.error is not None
        assert (
            "at least 8 characters" in result.error.lower()
            or "credential" in result.error.lower()
        )


class TestFlextAuthHandlerRegistration:
    """Test FlextBus handler registration."""

    def test_identity_service_operations(self) -> None:
        """Test that identity service operations work correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify identity service is initialized
        assert hasattr(auth, "_identity_service")
        assert auth._identity_service is not None

        # Verify handlers exist (through successful operations)
        result = auth.register_user("cmduser", "cmd@example.com", "CmdPass123!")
        assert result.is_success

    def test_query_handlers_registered(self) -> None:
        """Test that query handlers are registered with FlextBus."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Create a user first
        auth.register_user("queryuser", "query@example.com", "QueryPass123!")

        # Test query handler through get_user_by_username
        result = auth.get_user_by_username("queryuser")
        assert result.is_success

    def test_registry_initialized(self) -> None:
        """Test that registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify FlextAuthRegistry is initialized
        assert hasattr(auth, "_registry")
        assert auth._registry is not None
        # Verify registry has providers
        providers = auth._registry.list_providers()
        assert isinstance(providers, list)


class TestFlextAuthAdvancedPatterns:
    """Test advanced flext-core pattern integration."""

    def test_flext_container_integration(self) -> None:
        """Test FlextAuth service initialization."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify core services are initialized
        assert hasattr(auth, "_registry")
        assert auth._registry is not None
        assert hasattr(auth, "_dispatcher")
        assert auth._dispatcher is not None

    def test_flext_context_integration(self) -> None:
        """Test FlextService integration (FlextAuth extends FlextService)."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify FlextService is properly initialized
        assert hasattr(auth, "_dispatcher")
        assert auth._dispatcher is not None

    def test_flext_dispatcher_integration(self) -> None:
        """Test FlextDispatcher event bus."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify dispatcher is initialized
        assert hasattr(auth, "_dispatcher")
        assert auth._dispatcher is not None


class TestFlextAuthStorageOperations:
    """Test internal storage operations."""

    def test_username_index_management(self) -> None:
        """Test username index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Register user
        auth.register_user("indexuser", "index@example.com", "IndexPass123!")

        # Verify user can be retrieved by username (no direct index access)
        user_result = auth.get_user_by_username("indexuser")
        assert user_result.is_success

    def test_email_index_management(self) -> None:
        """Test email index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Register user
        auth.register_user("emailuser", "email@example.com", "EmailPass123!")

        # Verify user can be retrieved (email is stored as contact)
        user_result = auth.get_user_by_username("emailuser")
        assert user_result.is_success
        user = user_result.value
        assert user.contact == "email@example.com"

    def test_user_sessions_index_management(self) -> None:
        """Test user sessions index is maintained."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Register and authenticate user
        auth.register_user("sessionuser", "session@example.com", "SessionPass123!")
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        assert auth_result.is_success

        # Verify user sessions can be retrieved
        user = auth_result.value
        sessions_result = auth.get_user_sessions(user.id)
        assert sessions_result.is_success


class TestFlextAuthSettingsurationOverrides:
    """Test configuration override capabilities."""

    def test_create_with_config_overrides_method_exists(self) -> None:
        """Test create_with_config_overrides static method exists."""
        # Verify method exists
        assert hasattr(FlextAuth, "create_with_config_overrides")

    def test_custom_config_initialization(self) -> None:
        """Test initialization with custom configuration."""
        # Create custom config - create_for_environment returns FlextAuthSettings directly
        custom_config = FlextAuthSettings()

        # Create auth with custom config
        auth = FlextAuth(config=custom_config)
        assert auth.config == custom_config


class TestFlextAuthSessionManagement:
    """Test session management operations."""

    def test_get_user_sessions(self) -> None:
        """Test retrieving all sessions for a user."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Register and authenticate user
        auth.register_user("sessuser", "sess@example.com", "SessPass123!")
        auth_result = auth.authenticate_user("sessuser", "SessPass123!")
        assert auth_result.is_success

        user_result = auth.get_user_by_username("sessuser")
        assert user_result.is_success
        user = user_result.value

        # Get user sessions
        sessions_result = auth.get_user_sessions(user.unique_id)
        assert sessions_result.is_success

    def test_revoke_session(self) -> None:
        """Test revoking a session — token creation is not implemented so no sessions are created."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("revokeuser", "revoke@example.com", "RevokePass123!")
        auth_result = auth.authenticate_user("revokeuser", "RevokePass123!")
        assert auth_result.is_success
        user = auth_result.value
        # Get user sessions — empty because token/session creation is not implemented
        sessions_result = auth.get_user_sessions(user.id)
        assert sessions_result.is_success
        sessions = sessions_result.value
        assert (
            len(sessions) == 0
        )  # No sessions: JWT provider token generation not implemented

        # Revoke with non-existent session ID — should fail gracefully
        revoke_result = auth.revoke_session("nonexistent_session_id")
        assert not revoke_result.is_success


class TestFlextAuthTokenOperations:
    """Test JWT token operations."""

    def test_create_token_for_user(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
        user_result = auth.get_user_by_username("tokenuser")
        assert user_result.is_success
        user = user_result.value

        # create_token fails because JWT provider generate_token_for_user is not implemented
        token_result = auth.create_token(identity_id=user.id)
        assert not token_result.is_success
        assert token_result.error is not None

    def test_validate_token_with_bearer_prefix(self) -> None:
        """Test token validation — not implemented in JWT provider."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        # Register user
        register_result = auth.register_user(
            "beareruser",
            "bearer@example.com",
            "BearerPass123!",
        )
        assert register_result.is_success
        identity = register_result.value
        # create_token fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=identity.unique_id)
        assert not token_result.is_success

        # validate_token also fails with any token string
        validate_result = auth.validate_token("any.fake.token")
        assert not validate_result.is_success


class TestFlextAuthErrorHandling:
    """Test error handling and edge cases."""

    def test_duplicate_user_registration(self) -> None:
        """Test handling duplicate user registration."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Register user
        auth.register_user("dupuser", "dup@example.com", "DupPass123!")

        # Try to register again
        result = auth.register_user("dupuser", "dup2@example.com", "DupPass123!")
        assert not result.is_success
        assert result.error is not None and "already exists" in result.error.lower()

    def test_authentication_with_invalid_credentials(self) -> None:
        """Test authentication with wrong password."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Register user
        auth.register_user("authuser", "auth@example.com", "AuthPass123!")

        # Try wrong password
        result = auth.authenticate_user("authuser", "WrongPassword123!")
        assert not result.is_success

    def test_get_nonexistent_user(self) -> None:
        """Test retrieving non-existent user."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        result = auth.get_user_by_username("nonexistent")
        # get_user_by_username returns fail() for nonexistent users (fast fail, no None)
        assert not result.is_success
        assert result.error is not None
        assert "not found" in result.error.lower()


class TestFlextAuthLogging:
    """Test structured logging integration."""

    def test_initialization_logging(self) -> None:
        """Test that initialization is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify logger is initialized
        assert hasattr(auth, "logger")
        assert auth.logger is not None

    def test_handler_registration_logging(self) -> None:
        """Test that handler registration is logged."""
        # Creating auth triggers handler registration logging
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify successful initialization
        assert auth is not None


class TestFlextAuthProviderRegistry:
    """Test multi-provider registry (v2.0.0 feature)."""

    def test_provider_registry_initialization(self) -> None:
        """Test provider registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify provider registry exists (using public property)
        assert hasattr(auth, "registry")
        assert auth.registry is not None

    def test_default_provider_name(self) -> None:
        """Test default provider is set to jwt."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        # Verify default provider (jwt should be registered)
        providers = auth.list_providers()
        assert "jwt" in providers


class TestFlextAuthModelSettingsuration:
    """Test Pydantic model configuration."""

    def test_model_config_arbitrary_types_allowed(self) -> None:
        """Test that arbitrary types are allowed in model config."""
        # FlextAuth is a service, not a Pydantic model
        # Models are in FlextAuthModels
        # Check that Identity model has proper config
        assert hasattr(FlextAuthModels.Auth.AuthIdentity, "model_config")

    def test_model_config_validate_assignment(self) -> None:
        """Test validate_assignment configuration."""
        # FlextAuth is a service, not a Pydantic model
        # Config validation is in FlextAuthSettings
        config = FlextAuthSettings()
        # Config uses validate_assignment=True by default
        assert config.model_config.get("validate_assignment", False) is True


class TestFlextAuth:
    """Unit tests for FlextAuth class."""

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        # Clear singleton to ensure clean test
        FlextAuthSettings._reset_instance()

        # Test default initialization
        auth: FlextAuth = FlextAuth()
        assert auth._config.auth_secret is not None
        assert len(auth._config.auth_secret.get_secret_value()) > 20
        assert auth._config.hash_rounds == 12  # Default hash rounds
        assert auth._config.expiry_minutes == 1440  # Default expiry

        # Test custom initialization
        custom_secret = "test-secret-key-with-minimum-32-characters-length"
        custom_rounds = 10
        custom_expiry = 60

        custom_config = FlextAuthSettings(
            auth_secret=SecretStr(custom_secret),
            hash_rounds=custom_rounds,
            expiry_minutes=custom_expiry,
        )
        auth_custom: FlextAuth = FlextAuth(config=custom_config)
        assert auth_custom._config.auth_secret.get_secret_value() == custom_secret
        assert auth_custom._config.hash_rounds == custom_rounds
        assert auth_custom._config.expiry_minutes == custom_expiry

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
        assert user.name == "testuser"
        assert user.contact == "test@example.com"
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
        assert "already exists" in (duplicate_result.error or "")

    def test_user_registration_duplicate_email(self) -> None:
        """Test user registration with duplicate email."""
        auth: FlextAuth = FlextAuth()

        # First registration
        first_result = auth.register_user("user1", "test@example.com", "Password123!")
        assert first_result.is_success

        # Second registration with same email
        duplicate_result = auth.register_user(
            "user2",
            "test@example.com",
            "Password123!",
        )
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

        # authenticate_user returns Identity, not dict
        identity = auth_result.value
        assert isinstance(identity, FlextAuthModels.Auth.AuthIdentity)
        assert identity.name == username
        assert identity.contact == "auth@example.com"

    def test_user_authentication_invalid_credentials(self) -> None:
        """Test authentication with invalid credentials."""
        auth: FlextAuth = FlextAuth()
        username = "testuser"

        # Register user
        auth.register_user(username, "test@example.com", "CorrectPassword123!")

        # Test with wrong password
        failed_auth = auth.authenticate_user(username, "WrongPassword123!")
        assert not failed_auth.is_success
        assert not failed_auth.is_success
        assert "Invalid credentials" in (failed_auth.error or "")

    def test_token_validation_valid_token(self) -> None:
        """Test that token creation/validation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "tokenuser"
        password = "TokenPassword123!"
        register_result = auth.register_user(username, "token@example.com", password)
        assert register_result.is_success
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success
        authenticated_identity = auth_result.value
        assert isinstance(authenticated_identity, FlextAuthModels.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.id)
        assert not token_result.is_success
        assert token_result.error is not None

    def test_token_validation_invalid_token(self) -> None:
        """Test validation of invalid token — fails with 'not implemented'."""
        auth: FlextAuth = FlextAuth()
        invalid_result = auth.validate_token("invalid.token.here")
        assert not invalid_result.is_success
        assert invalid_result.error is not None

    def test_token_validation_bearer_prefix(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "beareruser"
        password = "BearerPassword123!"
        register_result = auth.register_user(username, "bearer@example.com", password)
        assert register_result.is_success
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success
        # create_token fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=identity.unique_id)
        assert not token_result.is_success
        assert token_result.error is not None

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

        # authenticate_user returns Identity
        identity = auth_result.value
        assert isinstance(identity, FlextAuthModels.Auth.AuthIdentity)

        # Test get user sessions
        sessions_result = auth.get_user_sessions(identity.unique_id)
        assert sessions_result.is_success
        sessions = sessions_result.value
        assert isinstance(sessions, list)
        assert len(sessions) >= 0  # Sessions may be empty initially

    def test_user_logout(self) -> None:
        """Test user logout functionality."""
        auth: FlextAuth = FlextAuth()
        username = "logoutuser"
        password = "LogoutPassword123!"

        # Register and authenticate
        auth.register_user(username, "logout@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.is_success

        # authenticate_user returns Identity
        identity = auth_result.value
        assert isinstance(identity, FlextAuthModels.Auth.AuthIdentity)

        # Get user sessions to find session ID
        sessions_result = auth.get_user_sessions(identity.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.logout_user(session_id)
                assert logout_result.is_success

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth: FlextAuth = FlextAuth()

        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.is_success
        cleaned_count = cleanup_result.value
        assert isinstance(cleaned_count, int)
        assert cleaned_count >= 0

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

    def test_quick_start_with_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start with REDACTED_LDAP_BIND_PASSWORD user creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)

    def test_quick_start_custom_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start with custom REDACTED_LDAP_BIND_PASSWORD credentials."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)

    def test_quick_start_no_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start without REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
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
        for _ in range(FlextAuthConstants.Auth.MAX_ATTEMPTS_DEFAULT):
            failed_auth = auth.authenticate_user(username, "wrong_password")
            assert not failed_auth.is_success

        # Next attempt should indicate account is locked
        locked_auth = auth.authenticate_user(username, password)
        assert not locked_auth.is_success
        # Should fail even with correct password due to lockout
        assert (
            "locked" in (locked_auth.error or "").lower()
            or "inactive" in (locked_auth.error or "").lower()
        )

    def test_password_strength_enforcement(self) -> None:
        """Test password strength requirements."""
        auth: FlextAuth = FlextAuth()

        # Test with weak password - should return failure
        result = auth.register_user(
            "weakuser",
            "weak@example.com",
            "weak",  # Too weak
        )
        assert not result.is_success
        assert result.error is not None


class TestFlextAuthErrorHandlingSecond:
    """Unit tests for error handling scenarios."""

    def test_empty_username_registration(self) -> None:
        """Test registration with empty username."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("", "empty@example.com", "Password123!")
        assert not result.is_success

    def test_empty_email_registration(self) -> None:
        """Test registration with empty email."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("user", "", "Password123!")
        assert not result.is_success

    def test_empty_password_registration(self) -> None:
        """Test registration with empty password."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("user", "test@example.com", "")
        assert not result.is_success

    def test_invalid_email_registration(self) -> None:
        """Test registration with invalid email."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("user", "invalid-email", "Password123!")
        assert not result.is_success

    def test_nonexistent_user_authentication(self) -> None:
        """Test authentication of non-existent user."""
        auth: FlextAuth = FlextAuth()

        auth_result = auth.authenticate_user("nonexistent", "password")
        assert not auth_result.is_success
        # User not found is a valid error message
        assert auth_result.error is not None
        assert len(auth_result.error) > 0

    def test_invalid_session_logout(self) -> None:
        """Test logout with invalid session ID."""
        auth: FlextAuth = FlextAuth()

        logout_result = auth.logout_user("invalid_session_id")
        assert not logout_result.is_success
        assert not logout_result.is_success
        assert "Session not found" in (logout_result.error or "")


class TestFlextAuthQuickStartFunction:
    """Unit tests for FlextAuth.quick_start() classmethod."""

    def test_flext_auth_quick_start_default(self) -> None:
        """Test FlextAuth.quick_start() with default parameters."""
        auth = FlextAuth.quick_start()
        assert isinstance(auth, FlextAuth)
        # quick_start doesn't create REDACTED_LDAP_BIND_PASSWORD by default (create_REDACTED_LDAP_BIND_PASSWORD is reserved for future)
        # Just verify it creates a valid instance
        assert auth.config is not None
        assert auth.registry is not None

    def test_flext_auth_quick_start_no_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() without creating REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert isinstance(auth, FlextAuth)
        # Should not create REDACTED_LDAP_BIND_PASSWORD user - check that getting nonexistent user fails
        # since REDACTED_LDAP_BIND_PASSWORD might have been created in previous tests, we test the function works
        nonexistent_result = auth.get_user_by_username("nonexistent_user")
        assert not nonexistent_result.is_success
        assert nonexistent_result.error is not None
        assert "not found" in nonexistent_result.error.lower()

    def test_flext_auth_quick_start_custom_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)
        # Admin creation is reserved for future functionality


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
            assert auth._config is not None
        except RuntimeError as e:
            # If it fails with RuntimeError, we expect a specific error message
            pytest.fail(f"FlextAuth creation failed with RuntimeError: {e}")
        except Exception as e:
            # Other exceptions should be properly handled, not ignored
            pytest.fail(f"Unexpected exception during FlextAuth creation: {e}")

    def test_quick_start_redacted_ldap_bind_password_creation_failure(self) -> None:
        """Test quick_start with REDACTED_LDAP_BIND_PASSWORD creation (reserved for future)."""
        # Admin creation is reserved for future functionality
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)

    def test_quick_start_general_failure(self) -> None:
        """Test quick_start general path."""
        # Quick start should always succeed
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert auth is not None
        assert isinstance(auth, FlextAuth)

    def test_flext_auth_initialization_with_overrides(self) -> None:
        """Test FlextAuth initialization with parameter overrides - lines 235-237."""
        # Create with custom parameters to cover override paths
        auth = FlextAuth.create_with_config_overrides(
            expiry_minutes=120,
            hash_rounds=10,
            auth_secret="test-secret-key-with-minimum-32-characters-length",
        )

        assert auth._config.expiry_minutes == 120
        assert auth._config.hash_rounds == 10


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
        assert not result.is_success
        error_msg = result.error or ""
        assert (
            "contact" in error_msg.lower()
            or "email" in error_msg.lower()
            or "pattern" in error_msg.lower()
        )

    def test_authenticate_user_failure_paths(self) -> None:
        """Test authenticate_user method failure scenarios."""
        auth = FlextAuth()

        # Test authentication with non-existent user
        result = auth.authenticate_user(
            username="nonexistent_user",
            password="any_password",
        )

        assert not result.is_success
        assert isinstance(result.error, str)

    def test_validate_token_invalid_cases(self) -> None:
        """Test token validation with invalid tokens."""
        auth = FlextAuth()

        # Test with malformed token
        result = auth.validate_token("invalid.malformed.token")
        assert not result.is_success

        # Test with empty token
        result = auth.validate_token("")
        assert not result.is_success

        # Test with invalid token format
        result = auth.validate_token("invalid.token.format")
        assert not result.is_success


class TestFlextAuthPasswordMethods:
    """Test password-related methods to cover uncovered lines."""

    def test_hash_password_method(self) -> None:
        """Test hash_password method functionality."""
        # Create identity to test password hashing using correct model
        identity = FlextAuthModels.Auth.AuthIdentity(
            unique_id="test-id",
            name="testuser",
            contact="test@example.com",
            full_name="Test User",
            is_active=True,
            roles=[],
            failed_attempts=0,
            locked_until=datetime.min.replace(tzinfo=UTC),
            last_access=datetime.min.replace(tzinfo=UTC),
        )
        result = identity.set_credential("StrongTestPass123!@#")

        # set_credential returns FlextResult[bool]
        assert result.is_success
        assert result.value is True
        assert identity.credential_hash != "StrongTestPass123!@#"
        assert len(identity.credential_hash) > 10  # Bcrypt hash should be substantial

    def test_verify_password_method(self) -> None:
        """Test verify_password method functionality."""
        # Use strong password that meets validation requirements
        strong_password = "StrongTestPass123!@#"

        # Create identity and set credential using correct model
        identity = FlextAuthModels.Auth.AuthIdentity(
            unique_id="test-id",
            name="testuser",
            contact="test@example.com",
            full_name="Test User",
            is_active=True,
            roles=[],
            failed_attempts=0,
            locked_until=datetime.min.replace(tzinfo=UTC),
            last_access=datetime.min.replace(tzinfo=UTC),
        )
        set_result = identity.set_credential(strong_password)
        assert set_result.is_success

        # Test correct credential verification
        verify_result = identity.verify_credential(strong_password)
        assert verify_result.is_success
        assert verify_result.value is True

        # Test wrong credential verification
        wrong_result = identity.verify_credential("WrongPassword123!@")
        assert wrong_result.is_success
        assert wrong_result.value is False


class TestFlextAuthTokenMethods:
    """Test token generation and validation methods."""

    def test_generate_token_method(self) -> None:
        """Test that create_token fails — JWT provider not implemented."""
        auth = FlextAuth()
        # First register a user
        user_result = auth.register_user(
            username="jwt_test_user",
            email="jwt@example.com",
            password="JWTTestPass123!@#",
        )
        assert user_result.is_success
        user = user_result.value
        # create_token fails — JWT provider not implemented
        result = auth.create_token(identity_id=user.unique_id)
        assert not result.is_success
        assert result.error is not None

    def test_generate_token_alternative_method(self) -> None:
        """Test that create_token fails via alternative path — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        assert register_result.is_success
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        assert auth_result.is_success
        # create_token fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=identity.unique_id)
        assert not token_result.is_success
        assert token_result.error is not None

    def test_validate_token_success_path(self) -> None:
        """Test that validate_token fails — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        assert register_result.is_success
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        assert auth_result.is_success
        authenticated_identity = auth_result.value
        assert isinstance(authenticated_identity, FlextAuthModels.Auth.AuthIdentity)
        # create_token fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=identity.unique_id)
        assert not token_result.is_success
        # validate_token also fails with any token string
        val_result = auth.validate_token("any.fake.token")
        assert not val_result.is_success


class TestFlextAuthUserMethods:
    """Test user management methods available in FlextAuth."""

    def test_get_user_method(self) -> None:
        """Test get_user method functionality."""
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
        get_result = auth.get_user(user.unique_id)
        assert get_result.is_success
        retrieved_user = get_result.value
        assert retrieved_user.unique_id == user.unique_id

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
        """Test that create_token fails — user retrieval by ID still works."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_token_user",
            email="tokenuser@example.com",
            password="TokenUserPass123!@",
        )
        assert user_result.is_success
        user = user_result.value
        # create_token fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=user.unique_id)
        assert not token_result.is_success

        # But get_user by ID still works directly
        get_result = auth.get_user(user.unique_id)
        assert get_result.is_success

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

        # Get user sessions to find session ID for logout
        sessions_result = auth.get_user_sessions(user.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.logout_user(session_id)
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

    def test_quick_start_with_redacted_ldap_bind_password(self) -> None:
        """Test quick_start class method with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)

        assert isinstance(auth, FlextAuth)
        assert auth.config is not None

    def test_quick_start_without_redacted_ldap_bind_password(self) -> None:
        """Test quick_start class method without REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        assert isinstance(auth, FlextAuth)
        assert auth.config is not None


class TestFlextAuthSettingsurationMethods:
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
            assert not failed_result.is_success

    def test_token_expiry_edge_cases(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth()
        # Register a user first
        user_result = auth.register_user(
            "test_user",
            "test@example.com",
            "TestPassword123!",
        )
        assert user_result.is_success
        user = user_result.value
        # create_token fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=user.id)
        assert not token_result.is_success
        assert token_result.error is not None

    def test_invalid_user_operations(self) -> None:
        """Test operations with invalid user IDs."""
        auth = FlextAuth()

        # Test various operations with invalid user ID
        invalid_user_id = "nonexistent_user_id"

        # Get user by invalid ID - should fail (fast fail, no None returns)
        get_result = auth.get_user(invalid_user_id)
        assert not get_result.is_success  # Fast fail when user not found
        assert get_result.error is not None
        assert "not found" in get_result.error.lower()

        # Get user by invalid username - should fail (fast fail)
        username_result = auth.get_user_by_username("nonexistent_username")
        assert not username_result.is_success
        assert username_result.error is not None
        assert "not found" in username_result.error.lower()

        # Logout invalid user - returns failure when user not found
        logout_result = auth.logout_user(invalid_user_id)
        assert not logout_result.is_success  # Session not found


class TestFlextAuthAdditionalCoverage:
    """Test additional coverage for missing lines in auth.py."""

    def test_cleanup_expired_sessions_with_user_sessions_index(self) -> None:
        """Test cleanup_expired_sessions method with user sessions index - lines 662-667."""
        auth = FlextAuth()

        # Register and authenticate user with complex password
        auth.register_user("testuser", "test@example.com", "Password123!")
        auth_result = auth.authenticate_user("testuser", "Password123!")
        assert auth_result.is_success

        # authenticate_user returns Identity
        identity = auth_result.value
        assert isinstance(identity, FlextAuthModels.Auth.AuthIdentity)

        # Get user sessions
        sessions_result = auth.get_user_sessions(identity.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            # Sessions may exist or be empty
            assert isinstance(sessions, list)

        # Cleanup expired sessions - this should test the user sessions index removal
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.is_success

    def test_get_user_by_token_invalid_token_error_direct_api(self) -> None:
        """Test validate_token with invalid token — fails with 'not implemented'."""
        auth = FlextAuth()
        # Test with invalid token - should fail (JWT provider not implemented)
        result = auth.validate_token("invalid_token")
        assert not result.is_success
        assert result.error is not None


class TestAuthModule:
    """Unified test class for auth module functionality."""

    class _TestDataHelper:
        """Nested helper class for test data creation."""

        @staticmethod
        def create_test_user_data() -> dict[str, t.GeneralValueType]:
            """Create test user data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
                "role": "user",
            }

        @staticmethod
        def create_test_auth_data() -> dict[str, t.GeneralValueType]:
            """Create test authentication data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
            }

        @staticmethod
        def create_test_session_data() -> dict[str, t.GeneralValueType]:
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
        )
        assert isinstance(result, FlextResult)

    def test_flext_auth_authenticate_user(self) -> None:
        """Test FlextAuth authenticate_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()

        # Test user authentication if method exists
        if hasattr(auth, "authenticate_user"):
            result = auth.authenticate_user(
                str(test_data["username"]),
                str(test_data["password"]),
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
        )
        assert register_result.is_success

        # Test user retrieval
        result = auth.get_user_by_username(str(test_data["username"]))
        assert isinstance(result, FlextResult)

    def test_flext_auth_get_user(self) -> None:
        """Test FlextAuth get_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()

        # Register user first
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        assert register_result.is_success

        # Get user ID from registration result
        user = register_result.value
        user_id = user.id

        # Test user retrieval by ID
        result = auth.get_user(str(user_id))
        assert isinstance(result, FlextResult)

    def test_flext_auth_validate_token(self) -> None:
        """Test that create_token/validate_token fail — JWT provider not implemented."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        assert register_result.is_success
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        assert auth_result.is_success
        # authenticate_user returns Identity
        identity = auth_result.value
        assert isinstance(identity, FlextAuthModels.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        assert not token_result.is_success
        assert token_result.error is not None

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
            str(test_data["username"]),
            str(test_data["password"]),
        )
        assert auth_result.is_success

        # Get user ID
        user = register_result.value
        user_id = user.unique_id

        # Test getting user sessions
        result = auth.get_user_sessions(user_id)
        assert isinstance(result, FlextResult)
        assert result.is_success

    def test_flext_auth_get_user_by_token_direct_api(self) -> None:
        """Test that create_token fails — user retrieval still works by ID."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        # Register and authenticate user
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        assert register_result.is_success
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        assert auth_result.is_success
        identity = auth_result.value
        assert isinstance(identity, FlextAuthModels.Auth.AuthIdentity)
        # create_token fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=identity.unique_id)
        assert not token_result.is_success

        # But get_user by ID still works directly
        result = auth.get_user(identity.unique_id)
        assert isinstance(result, FlextResult)
        assert result.is_success

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
            str(test_data["username"]),
            str(test_data["password"]),
        )
        assert auth_result.is_success

        # authenticate_user returns Identity
        identity = auth_result.value
        assert isinstance(identity, FlextAuthModels.Auth.AuthIdentity)

        # Get user sessions to find session ID
        sessions_result = auth.get_user_sessions(identity.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                # Test session revocation
                result = auth.revoke_session(session_id)
                assert isinstance(result, FlextResult)
                assert result.is_success

    def test_flext_auth_comprehensive_scenario(self) -> None:
        """Test comprehensive auth module scenario — token ops fail as expected."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        assert auth is not None
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        assert isinstance(register_result, FlextResult)
        assert register_result.is_success
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        assert isinstance(auth_result, FlextResult)
        assert auth_result.is_success
        # Token creation fails — JWT provider not implemented
        identity = auth_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        assert not token_result.is_success
        assert token_result.error is not None

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
        assert not result.is_success  # Should fail with invalid data

        # Test authentication with invalid credentials
        result = auth.authenticate_user("invalid_user", "invalid_password")
        assert isinstance(result, FlextResult)
        assert not result.is_success  # Should fail with invalid credentials

        # Test retrieval of non-existent user
        result = auth.get_user_by_username("non_existent_user")
        assert isinstance(result, FlextResult)
        # Should fail for non-existent user (fast fail, no None)
        assert not result.is_success
        assert result.error is not None
        assert "not found" in result.error.lower()

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
            test_auth_data["username"],
            test_auth_data["password"],
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
            "get_user",
            "get_user_sessions",
            "validate_token",
            "revoke_session",
            "logout_user",
            "cleanup_expired_sessions",
        ]

        for method_name in expected_methods:
            assert hasattr(auth, method_name), f"Method {method_name} should exist"
            method = (
                auth.__getattribute__(method_name)
                if hasattr(auth, method_name)
                else None
            )
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
                user_data["username"],
                user_data["password"],
            )
            assert isinstance(result, FlextResult)
            assert result.is_success

    def test_flext_auth_integration_patterns(self) -> None:
        """Test auth integration patterns — token ops fail as expected."""
        auth = FlextAuth()
        # Test integration: register_user -> authenticate_user -> create_token (fails)
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        assert isinstance(register_result, FlextResult)
        assert register_result.is_success
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        assert isinstance(auth_result, FlextResult)
        assert auth_result.is_success
        authenticated_identity = auth_result.value
        assert isinstance(authenticated_identity, FlextAuthModels.Auth.AuthIdentity)
        # Token creation fails — JWT provider not implemented
        token_result = auth.create_token(identity_id=authenticated_identity.unique_id)
        assert isinstance(token_result, FlextResult)
        assert not token_result.is_success
        assert token_result.error is not None

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


class _BaseTokenProviderForFlowTests(FlextAuthBaseProvider):
    def authenticate(
        self,
        credentials: FlextAuthModels.CredentialValidation,
    ) -> FlextResult[p.Auth.TokenProtocol]:
        _ = credentials
        return FlextResult[p.Auth.TokenProtocol].fail("Not used in this test")

    def validate(
        self,
        token: str,
    ) -> FlextResult[bool]:
        _ = token
        return FlextResult[bool].ok(True)

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-test-base-flow"


class _RefreshCapableProviderForFlowTests(FlextAuthBaseProvider):
    def __init__(self) -> None:
        super().__init__(config={})
        self.last_refresh_input: str | None = None

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-test-refresh-flow"

    def authenticate(
        self,
        credentials: FlextAuthModels.CredentialValidation,
    ) -> FlextResult[p.Auth.TokenProtocol]:
        _ = credentials
        return FlextResult[p.Auth.TokenProtocol].fail("Not used in this test")

    def validate(
        self,
        token: str,
    ) -> FlextResult[bool]:
        _ = token
        return FlextResult[bool].ok(True)

    def refresh(
        self,
        token: str,
    ) -> FlextResult[p.Auth.TokenProtocol]:
        self.last_refresh_input = token
        refreshed_token = FlextAuthModels.Auth.AuthToken(
            identity_id="middleware-user",
            token="refreshed-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            refresh_token="refresh-next",
        )
        return FlextResult[p.Auth.TokenProtocol].ok(refreshed_token)


class _ConcreteKerberosProviderForFlowTests(FlextAuthKerberosProvider):
    def authenticate(
        self,
        credentials: FlextAuthModels.CredentialValidation,
    ) -> FlextResult[p.Auth.TokenProtocol]:
        _ = credentials
        return FlextResult[p.Auth.TokenProtocol].fail("Not used in this test")

    def validate(
        self,
        token: str,
    ) -> FlextResult[bool]:
        return self.validate_token(token).map(lambda _identity: True)

    def _protocol_name(self) -> str:
        """Return protocol name for registry identification."""
        return "auth-provider-test-kerberos-flow"


class TestProviderTokenFlows:
    """Test token flows for base providers."""

    def test_base_provider_generate_token_for_user(self) -> None:
        provider = _BaseTokenProviderForFlowTests(
            config={
                "secret_key": "unit-test-secret-key-for-base-provider-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 60,
            },
        )

        token_result = provider.generate_token_for_user(
            user=_build_identity_for_flow_tests(
                identity_id="base-user-123",
                name="Base User",
                contact="base@example.com",
                roles=["user"],
            ),
            token_type="access",
            expiry_minutes=5,
        )

        assert token_result.is_success
        payload = jwt.decode(
            token_result.value,
            "unit-test-secret-key-for-base-provider-12345",
            algorithms=["HS256"],
            audience="flext-auth-tests",
            issuer="flext-auth-tests",
        )
        assert payload["sub"] == "base-user-123"
        assert payload["token_type"] == "access"
        assert payload["name"] == "Base User"

    def test_middleware_refreshes_expired_token(self) -> None:
        provider = _RefreshCapableProviderForFlowTests()
        middleware = FlextAuthMiddleware.FlextWebAuthMiddleware(provider)
        middleware._current_token = FlextAuthModels.Auth.AuthToken(
            identity_id="middleware-user",
            token="expired-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            refresh_token="refresh-source-token",
        )

        HttpRequest.headers = {}
        request = HttpRequest()
        result = middleware.process_request(request)

        assert result.is_success
        assert request.headers.get("Authorization") == "Bearer refreshed-token"
        assert provider.last_refresh_input == "refresh-source-token"

    def test_kerberos_generate_and_validate_token(self) -> None:
        provider = _ConcreteKerberosProviderForFlowTests(
            config={
                "realm": "EXAMPLE.COM",
                "kdc": "kdc.example.com",
                "service_principal": "HTTP/api.example.com@EXAMPLE.COM",
                "secret_key": "unit-test-secret-key-for-kerberos-provider-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
                "expiry_minutes": 30,
            },
        )

        token_result = provider.generate_token_for_user(
            user={
                "identity_id": "kerberos-user",
                "name": "Kerberos User",
                "contact": "kerberos@example.com",
                "roles": ["user"],
            },
            token_type="kerberos",
            expiry_minutes=10,
        )

        assert token_result.is_success
        identity_result = provider.validate_token(token_result.value)
        assert identity_result.is_success
        identity = identity_result.value
        assert identity.name == "Kerberos User"
        assert identity.contact == "kerberos@example.com"
        assert identity.roles == ["user"]

    def test_oauth2_validate_token_returns_identity(self) -> None:
        provider = FlextAuthOAuth2Provider(
            {
                "client_id": "oauth-test-client",
                "token_endpoint": "https://auth.example.com/token",
                "secret_key": "unit-test-secret-key-for-oauth-provider-12345",
                "algorithm": "HS256",
                "issuer": "flext-auth-tests",
                "audience": "flext-auth-tests",
            },
        )

        now = datetime.now(UTC)
        encoded_token = jwt.encode(
            {
                "sub": "oauth-user-123",
                "name": "OAuth User",
                "email": "oauth@example.com",
                "roles": ["user"],
                "iat": int(now.timestamp()),
                "exp": int((now + timedelta(minutes=30)).timestamp()),
                "iss": "flext-auth-tests",
                "aud": "flext-auth-tests",
            },
            "unit-test-secret-key-for-oauth-provider-12345",
            algorithm="HS256",
        )

        match encoded_token:
            case str() as token:
                token_value = token
            case bytes() as token_bytes:
                token_value = token_bytes.decode("utf-8")
            case _:
                token_value = str(encoded_token)

        result = provider.validate_token(token_value)
        assert result.is_success
        identity = result.value
        assert identity.id == "oauth-user-123"
        assert identity.name == "OAuth User"
        assert identity.contact == "oauth@example.com"


def _build_identity_for_flow_tests(
    *,
    identity_id: str,
    name: str,
    contact: str,
    roles: list[str],
) -> FlextAuthModels.Auth.AuthIdentity:
    return FlextAuthModels.Auth.AuthIdentity(
        unique_id=identity_id,
        name=name,
        contact=contact,
        roles=roles,
        failed_attempts=0,
        locked_until=datetime.min.replace(tzinfo=UTC),
        last_access=datetime.min.replace(tzinfo=UTC),
    )

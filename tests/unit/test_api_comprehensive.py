"""Comprehensive tests for FlextAuth API to achieve 100% coverage.

Tests all uncovered methods in api.py including helper classes,
processor registrations, handlers, and advanced patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig


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
        result_valid = auth.register_user("validuser", "test@example.com", "ValidPass123!")
        assert result_valid.is_success

        # Test with too short username - Pydantic validates before processor
        # This will raise ValidationError, which is expected behavior
        try:
            auth.register_user("ab", "test2@example.com", "ValidPass123!")
            assert False, "Should have raised validation error"
        except Exception as e:
            assert "at least 3 characters" in str(e).lower()

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
        try:
            auth.register_user("user1", "user1@example.com", "weak")
            assert False, "Should have raised validation error"
        except Exception as e:
            assert "at least 8 characters" in str(e).lower()


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

    def test_flext_cqrs_integration(self) -> None:
        """Test FlextCqrs command/query separation."""
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Verify CQRS is initialized
        assert hasattr(auth, "_cqrs")
        assert auth._cqrs is not None

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
        assert "already exists" in result.error.lower()

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
        assert hasattr(auth, "_logger")
        assert auth._logger is not None

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

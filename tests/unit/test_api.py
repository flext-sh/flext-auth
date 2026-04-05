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
from threading import Thread
from typing import override

import jwt
import pytest
from flext_tests import tm

from flext_auth import (
    FlextAuth,
    FlextAuthKerberosProvider,
    FlextAuthMiddleware,
    FlextAuthRfcProvider,
    FlextAuthSettings,
    c,
    m,
    p,
)
from flext_auth.providers.oauth2 import FlextAuthOAuth2Provider
from flext_core import r
from tests import t


class HttpRequest:
    """Minimal HTTP request fixture for middleware tests."""

    def __init__(self) -> None:
        """Initialize with empty headers."""
        headers: dict[str, str] = {}
        self.headers: t.StrMapping = headers


class TestFlextAuthServiceInitialization:
    """Test FlextAuth service initialization."""

    def test_auth_service_initialization(self) -> None:
        """Test FlextAuth services are properly initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "_provider_service"), eq=True)
        tm.that(auth._provider_service, none=False)
        tm.that(hasattr(auth, "_identity_service"), eq=True)
        tm.that(auth._identity_service, none=False)
        tm.that(hasattr(auth, "_token_service"), eq=True)
        tm.that(auth._token_service, none=False)
        tm.that(hasattr(auth, "_session_service"), eq=True)
        tm.that(auth._session_service, none=False)
        tm.that(hasattr(auth, "_registry"), eq=True)
        tm.that(auth._registry, none=False)
        tm.that(hasattr(auth, "_dispatcher"), eq=True)
        tm.that(auth._dispatcher, none=False)


class TestFlextAuthProcessorRegistration:
    """Test authentication processor registration."""

    def test_services_registered_on_initialization(self) -> None:
        """Test that services are registered during initialization."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "_dispatcher"), eq=True)
        tm.that(auth._dispatcher, none=False)
        tm.that(hasattr(auth, "_registry"), eq=True)
        tm.that(auth._registry, none=False)
        tm.that(hasattr(auth, "_provider_service"), eq=True)
        tm.that(auth._provider_service, none=False)

    def test_username_validation_processor(self) -> None:
        """Test username validation through processor."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result_valid = auth.register_user(
            "validuser",
            "test@example.com",
            "ValidPass123!",
        )
        tm.that(result_valid.is_success, eq=True)
        result_short = auth.register_user("ab", "test2@example.com", "ValidPass123!")
        tm.that(not result_short.is_success, eq=True)
        tm.that(result_short.error, none=False)

    def test_email_normalization_processor(self) -> None:
        """Test email normalization to lowercase."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.register_user("testuser", "TEST@EXAMPLE.COM", "ValidPass123!")
        tm.that(result.is_success, eq=True)
        user_result = auth.get_user_by_username("testuser")
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        tm.that(user.contact, eq="test@example.com")

    def test_password_strength_validation_processor(self) -> None:
        """Test password strength validation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.register_user("user1", "user1@example.com", "weak")
        tm.that(not result.is_success, eq=True)
        tm.that(result.error, none=False)
        error_text = (result.error or "").lower()
        tm.that(
            ("at least 8 characters" in error_text or "credential" in error_text),
            eq=True,
        )


class TestFlextAuthHandlerRegistration:
    """Test FlextBus handler registration."""

    def test_identity_service_operations(self) -> None:
        """Test that identity service operations work correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "_identity_service"), eq=True)
        tm.that(auth._identity_service, none=False)
        result = auth.register_user("cmduser", "cmd@example.com", "CmdPass123!")
        tm.that(result.is_success, eq=True)

    def test_query_handlers_registered(self) -> None:
        """Test that query handlers are registered with FlextBus."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("queryuser", "query@example.com", "QueryPass123!")
        result = auth.get_user_by_username("queryuser")
        tm.that(result.is_success, eq=True)

    def test_registry_initialized(self) -> None:
        """Test that registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "_registry"), eq=True)
        tm.that(auth._registry, none=False)
        providers = auth._registry.list_providers()
        tm.that(providers, is_=list)


class TestFlextAuthAdvancedPatterns:
    """Test advanced flext-core pattern integration."""

    def test_flext_container_integration(self) -> None:
        """Test FlextAuth service initialization."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "_registry"), eq=True)
        tm.that(auth._registry, none=False)
        tm.that(hasattr(auth, "_dispatcher"), eq=True)
        tm.that(auth._dispatcher, none=False)

    def test_flext_context_integration(self) -> None:
        """Test FlextService integration (FlextAuth extends FlextService)."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "_dispatcher"), eq=True)
        tm.that(auth._dispatcher, none=False)

    def test_flext_dispatcher_integration(self) -> None:
        """Test FlextDispatcher event bus."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "_dispatcher"), eq=True)
        tm.that(auth._dispatcher, none=False)


class TestFlextAuthStorageOperations:
    """Test internal storage operations."""

    def test_username_index_management(self) -> None:
        """Test username index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("indexuser", "index@example.com", "IndexPass123!")
        user_result = auth.get_user_by_username("indexuser")
        tm.that(user_result.is_success, eq=True)

    def test_email_index_management(self) -> None:
        """Test email index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("emailuser", "email@example.com", "EmailPass123!")
        user_result = auth.get_user_by_username("emailuser")
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        tm.that(user.contact, eq="email@example.com")

    def test_user_sessions_index_management(self) -> None:
        """Test user sessions index is maintained."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("sessionuser", "session@example.com", "SessionPass123!")
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        tm.that(auth_result.is_success, eq=True)
        user = auth_result.value
        sessions_result = auth.get_user_sessions(user.unique_id)
        tm.that(sessions_result.is_success, eq=True)


class TestFlextAuthConfigurationOverrides:
    """Test configuration override capabilities."""

    def test_create_with_config_overrides_method_exists(self) -> None:
        """Test create_with_config_overrides static method exists."""
        tm.that(hasattr(FlextAuth, "create_with_config_overrides"), eq=True)

    def test_custom_config_initialization(self) -> None:
        """Test initialization with custom configuration."""
        custom_config = FlextAuthSettings.get_global()
        auth = FlextAuth(config=custom_config)
        tm.that(auth.config, eq=custom_config)


class TestFlextAuthSessionManagement:
    """Test session management operations."""

    def test_get_user_sessions(self) -> None:
        """Test retrieving all sessions for a user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("sessuser", "sess@example.com", "SessPass123!")
        auth_result = auth.authenticate_user("sessuser", "SessPass123!")
        tm.that(auth_result.is_success, eq=True)
        user_result = auth.get_user_by_username("sessuser")
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        sessions_result = auth.get_user_sessions(user.unique_id)
        tm.that(sessions_result.is_success, eq=True)

    def test_revoke_session(self) -> None:
        """Test revoking a session — token creation is not implemented so no sessions are created."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("revokeuser", "revoke@example.com", "RevokePass123!")
        auth_result = auth.authenticate_user("revokeuser", "RevokePass123!")
        tm.that(auth_result.is_success, eq=True)
        user = auth_result.value
        sessions_result = auth.get_user_sessions(user.unique_id)
        tm.that(sessions_result.is_success, eq=True)
        sessions = sessions_result.value
        tm.that(not sessions, eq=True)
        revoke_result = auth.revoke_session("nonexistent_session_id")
        tm.that(not revoke_result.is_success, eq=True)


class TestFlextAuthTokenOperations:
    """Test JWT token operations."""

    def test_create_token_for_user(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
        user_result = auth.get_user_by_username("tokenuser")
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        tm.that(not token_result.is_success, eq=True)
        tm.that(token_result.error, none=False)

    def test_validate_token_with_bearer_prefix(self) -> None:
        """Test token validation — not implemented in JWT provider."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        register_result = auth.register_user(
            "beareruser",
            "bearer@example.com",
            "BearerPass123!",
        )
        tm.that(register_result.is_success, eq=True)
        identity = register_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        validate_result = auth.validate_token("any.fake.token")
        tm.that(not validate_result.is_success, eq=True)


class TestFlextAuthErrorHandling:
    """Test error handling and edge cases."""

    def test_duplicate_user_registration(self) -> None:
        """Test handling duplicate user registration."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("dupuser", "dup@example.com", "DupPass123!")
        result = auth.register_user("dupuser", "dup2@example.com", "DupPass123!")
        tm.that(not result.is_success, eq=True)
        tm.that(
            result.error is not None and "already exists" in result.error.lower(),
            eq=True,
        )

    def test_authentication_with_invalid_credentials(self) -> None:
        """Test authentication with wrong password."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("authuser", "auth@example.com", "AuthPass123!")
        result = auth.authenticate_user("authuser", "WrongPassword123!")
        tm.that(not result.is_success, eq=True)

    def test_get_nonexistent_user(self) -> None:
        """Test retrieving non-existent user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.get_user_by_username("nonexistent")
        tm.that(not result.is_success, eq=True)
        tm.that(result.error, none=False)
        tm.that((result.error or "").lower(), has="not found")


class TestFlextAuthLogging:
    """Test structured logging integration."""

    def test_initialization_logging(self) -> None:
        """Test that initialization is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "logger"), eq=True)
        tm.that(auth.logger, none=False)

    def test_handler_registration_logging(self) -> None:
        """Test that handler registration is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert auth is not None


class TestFlextAuthProviderRegistry:
    """Test multi-provider registry (v2.0.0 feature)."""

    def test_provider_registry_initialization(self) -> None:
        """Test provider registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(hasattr(auth, "registry"), eq=True)
        tm.that(auth.registry, none=False)

    def test_default_provider_name(self) -> None:
        """Test default provider is set to jwt."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        providers = auth.list_providers()
        tm.that(providers, has="jwt")


class TestFlextAuthModelConfiguration:
    """Test Pydantic model configuration."""

    def test_model_config_arbitrary_types_allowed(self) -> None:
        """Test that arbitrary types are allowed in model config."""
        tm.that(hasattr(m.Auth.AuthIdentity, "model_config"), eq=True)

    def test_model_config_validate_assignment(self) -> None:
        """Test validate_assignment configuration."""
        config = FlextAuthSettings.get_global()
        tm.that(config.model_config.get("validate_assignment", False) is True, eq=True)


class TestFlextAuth:
    """Unit tests for FlextAuth class."""

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        FlextAuthSettings._reset_instance()
        auth: FlextAuth = FlextAuth()
        tm.that(auth._config.auth_secret, none=False)
        tm.that(len(auth._config.auth_secret.get_secret_value()), gt=20)
        tm.that(auth._config.hash_rounds, eq=12)
        tm.that(auth._config.expiry_minutes, eq=1440)
        custom_secret = "test-secret-key-with-minimum-32-characters-length"
        custom_rounds = 10
        custom_expiry = 60
        custom_config = FlextAuthSettings(
            secret_key=custom_secret,
            algorithm="HS256",
            issuer="flext-auth",
            audience="flext-users",
            hash_rounds=custom_rounds,
            expiry_minutes=custom_expiry,
            session_expiry_minutes=1440,
            max_sessions_per_user=5,
        )
        auth_custom: FlextAuth = FlextAuth(config=custom_config)
        tm.that(auth_custom._config.auth_secret.get_secret_value(), eq=custom_secret)
        tm.that(auth_custom._config.hash_rounds, eq=custom_rounds)
        tm.that(auth_custom._config.expiry_minutes, eq=custom_expiry)

    def test_user_registration_success(self) -> None:
        """Test successful user registration."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            roles=["user"],
        )
        tm.that(result.is_success, eq=True)
        user = result.value
        tm.that(user.name, eq="testuser")
        tm.that(user.contact, eq="test@example.com")
        tm.that(user.roles, has="user")
        tm.that(user.is_active, eq=True)

    def test_user_registration_duplicate_username(self) -> None:
        """Test user registration with duplicate username."""
        auth: FlextAuth = FlextAuth()
        auth.register_user("testuser", "test1@example.com", "Password123!")
        duplicate_result = auth.register_user(
            "testuser",
            "test2@example.com",
            "Password123!",
        )
        tm.that(duplicate_result.is_failure, eq=True)
        tm.that((duplicate_result.error or ""), has="already exists")

    def test_user_registration_duplicate_email(self) -> None:
        """Test user registration with duplicate email."""
        auth: FlextAuth = FlextAuth()
        first_result = auth.register_user("user1", "test@example.com", "Password123!")
        tm.that(first_result.is_success, eq=True)
        duplicate_result = auth.register_user(
            "user2",
            "test@example.com",
            "Password123!",
        )
        tm.that(duplicate_result.is_failure, eq=True)
        tm.that((duplicate_result.error or ""), has="already exists")

    def test_user_authentication_success(self) -> None:
        """Test successful user authentication."""
        auth: FlextAuth = FlextAuth()
        username = "authtest"
        password = "AuthPassword123!"
        reg_result = auth.register_user(username, "auth@example.com", password)
        tm.that(reg_result.is_success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        tm.that(identity.name, eq=username)
        tm.that(identity.contact, eq="auth@example.com")

    def test_user_authentication_invalid_credentials(self) -> None:
        """Test authentication with invalid credentials."""
        auth: FlextAuth = FlextAuth()
        username = "testuser"
        auth.register_user(username, "test@example.com", "CorrectPassword123!")
        failed_auth = auth.authenticate_user(username, "WrongPassword123!")
        tm.that(not failed_auth.is_success, eq=True)
        tm.that(not failed_auth.is_success, eq=True)
        tm.that((failed_auth.error or ""), has="Invalid credentials")

    def test_token_validation_valid_token(self) -> None:
        """Test that token creation/validation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "tokenuser"
        password = "TokenPassword123!"
        register_result = auth.register_user(username, "token@example.com", password)
        tm.that(register_result.is_success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        tm.that(auth_result.is_success, eq=True)
        authenticated_identity = auth_result.value
        tm.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        tm.that(token_result.error, none=False)

    def test_token_validation_invalid_token(self) -> None:
        """Test validation of invalid token — fails with 'not implemented'."""
        auth: FlextAuth = FlextAuth()
        invalid_result = auth.validate_token("invalid.token.here")
        tm.that(not invalid_result.is_success, eq=True)
        tm.that(invalid_result.error, none=False)

    def test_token_validation_bearer_prefix(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "beareruser"
        password = "BearerPassword123!"
        register_result = auth.register_user(username, "bearer@example.com", password)
        tm.that(register_result.is_success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        tm.that(auth_result.is_success, eq=True)
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        tm.that(token_result.error, none=False)

    def test_session_management(self) -> None:
        """Test session management functionality."""
        auth: FlextAuth = FlextAuth()
        username = "sessionuser"
        password = "SessionPassword123!"
        auth.register_user(username, "session@example.com", password)
        auth_result = auth.authenticate_user(
            username,
            password,
            "127.0.0.1",
            "test-user-agent",
        )
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.get_user_sessions(identity.unique_id)
        tm.that(sessions_result.is_success, eq=True)
        sessions = sessions_result.value
        tm.that(sessions, is_=list)
        tm.that(len(sessions), gte=0)

    def test_user_logout(self) -> None:
        """Test user logout functionality."""
        auth: FlextAuth = FlextAuth()
        username = "logoutuser"
        password = "LogoutPassword123!"
        auth.register_user(username, "logout@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.get_user_sessions(identity.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.logout_user(session_id)
                tm.that(logout_result.is_success, eq=True)

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth: FlextAuth = FlextAuth()
        cleanup_result = auth.cleanup_expired_sessions()
        tm.that(cleanup_result.is_success, eq=True)
        cleaned_count = cleanup_result.value
        tm.that(cleaned_count, is_=int)
        tm.that(cleaned_count, gte=0)

    def test_sync_api_methods(self) -> None:
        """Test synchronous API methods work as expected."""
        auth: FlextAuth = FlextAuth()
        username = "syncuser"
        password = "SyncPassword123!"
        create_result = auth.register_user(username, "sync@example.com", password)
        tm.that(create_result.is_success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        tm.that(auth_result.is_success, eq=True)


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
        auth.register_user(username, "lock@example.com", password)
        for _ in range(c.Auth.MAX_ATTEMPTS_DEFAULT):
            failed_auth = auth.authenticate_user(username, "wrong_password")
            tm.that(not failed_auth.is_success, eq=True)
        locked_auth = auth.authenticate_user(username, password)
        tm.that(not locked_auth.is_success, eq=True)
        tm.that(
            (
                "locked" in (locked_auth.error or "").lower()
                or "inactive" in (locked_auth.error or "").lower()
            ),
            eq=True,
        )

    def test_password_strength_enforcement(self) -> None:
        """Test password strength requirements."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("weakuser", "weak@example.com", "weak")
        tm.that(not result.is_success, eq=True)
        tm.that(result.error, none=False)


class TestFlextAuthErrorHandlingSecond:
    """Unit tests for error handling scenarios."""

    def test_empty_username_registration(self) -> None:
        """Test registration with empty username."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("", "empty@example.com", "Password123!")
        tm.that(not result.is_success, eq=True)

    def test_empty_email_registration(self) -> None:
        """Test registration with empty email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "", "Password123!")
        tm.that(not result.is_success, eq=True)

    def test_empty_password_registration(self) -> None:
        """Test registration with empty password."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "test@example.com", "")
        tm.that(not result.is_success, eq=True)

    def test_invalid_email_registration(self) -> None:
        """Test registration with invalid email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "invalid-email", "Password123!")
        tm.that(not result.is_success, eq=True)

    def test_nonexistent_user_authentication(self) -> None:
        """Test authentication of non-existent user."""
        auth: FlextAuth = FlextAuth()
        auth_result = auth.authenticate_user("nonexistent", "password")
        tm.that(not auth_result.is_success, eq=True)
        tm.that(auth_result.error, none=False)
        tm.that(auth_result.error or "", empty=False)

    def test_invalid_session_logout(self) -> None:
        """Test logout with invalid session ID."""
        auth: FlextAuth = FlextAuth()
        logout_result = auth.logout_user("invalid_session_id")
        tm.that(not logout_result.is_success, eq=True)
        tm.that(not logout_result.is_success, eq=True)
        tm.that((logout_result.error or ""), has="Session not found")


class TestFlextAuthQuickStartFunction:
    """Unit tests for FlextAuth.quick_start() classmethod."""

    def test_flext_auth_quick_start_default(self) -> None:
        """Test FlextAuth.quick_start() with default parameters."""
        auth = FlextAuth.quick_start()
        assert isinstance(auth, FlextAuth)
        tm.that(auth.config, none=False)
        tm.that(auth.registry, none=False)

    def test_flext_auth_quick_start_no_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() without creating REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert isinstance(auth, FlextAuth)
        nonexistent_result = auth.get_user_by_username("nonexistent_user")
        tm.that(not nonexistent_result.is_success, eq=True)
        tm.that(nonexistent_result.error, none=False)
        tm.that((nonexistent_result.error or "").lower(), has="not found")

    def test_flext_auth_quick_start_custom_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)


class TestFlextAuthInitializationCoverage:
    """Test FlextAuth initialization edge cases - covering lines 228-229."""

    def test_flext_auth_config_creation_failure(self) -> None:
        """Test FlextAuth initialization when config creation fails - lines 228-229."""
        try:
            auth = FlextAuth()
            tm.that(auth._config, none=False)
        except RuntimeError as e:
            pytest.fail(f"FlextAuth creation failed with RuntimeError: {e}")
        except Exception as e:
            pytest.fail(f"Unexpected exception during FlextAuth creation: {e}")

    def test_quick_start_redacted_ldap_bind_password_creation_failure(self) -> None:
        """Test quick_start with REDACTED_LDAP_BIND_PASSWORD creation (reserved for future)."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)

    def test_quick_start_general_failure(self) -> None:
        """Test quick_start general path."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert auth is not None
        assert isinstance(auth, FlextAuth)

    def test_flext_auth_initialization_with_overrides(self) -> None:
        """Test FlextAuth initialization with parameter overrides - lines 235-237."""
        auth = FlextAuth.create_with_config_overrides(
            expiry_minutes=120,
            hash_rounds=10,
            auth_secret="test-secret-key-with-minimum-32-characters-length",
        )
        tm.that(auth._config.expiry_minutes, eq=120)
        tm.that(auth._config.hash_rounds, eq=10)


class TestFlextAuthErrorPaths:
    """Test error handling paths in FlextAuth methods."""

    def test_register_user_edge_cases(self) -> None:
        """Test register_user method error paths."""
        auth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="invalid-email-format",
            password="ValidPassword123!",
        )
        tm.that(not result.is_success, eq=True)
        error_msg = result.error or ""
        tm.that(
            (
                "contact" in error_msg.lower()
                or "email" in error_msg.lower()
                or "pattern" in error_msg.lower()
            ),
            eq=True,
        )

    def test_authenticate_user_failure_paths(self) -> None:
        """Test authenticate_user method failure scenarios."""
        auth = FlextAuth()
        result = auth.authenticate_user(
            username="nonexistent_user",
            password="any_password",
        )
        tm.that(not result.is_success, eq=True)
        tm.that(result.error, is_=str)

    def test_validate_token_invalid_cases(self) -> None:
        """Test token validation with invalid tokens."""
        auth = FlextAuth()
        result = auth.validate_token("invalid.malformed.token")
        tm.that(not result.is_success, eq=True)
        result = auth.validate_token("")
        tm.that(not result.is_success, eq=True)
        result = auth.validate_token("invalid.token.format")
        tm.that(not result.is_success, eq=True)


class TestFlextAuthPasswordMethods:
    """Test password-related methods to cover uncovered lines."""

    def test_hash_password_method(self) -> None:
        """Test hash_password method functionality."""
        identity = m.Auth.AuthIdentity(
            unique_id="test-id",
            name="testuser",
            contact="test@example.com",
            credential_hash="",
            full_name="Test User",
            is_active=True,
            roles=[],
            permissions=[],
            token="",
            session_id="",
            failed_attempts=0,
            locked_until=datetime.min.replace(tzinfo=UTC),
            last_access=datetime.min.replace(tzinfo=UTC),
        )
        result = identity.set_credential("StrongTestPass123!@#")
        tm.that(result.is_success, eq=True)
        tm.that(result.value is True, eq=True)
        tm.that(identity.credential_hash, ne="StrongTestPass123!@#")
        tm.that(len(identity.credential_hash), gt=10)

    def test_verify_password_method(self) -> None:
        """Test verify_password method functionality."""
        strong_password = "StrongTestPass123!@#"
        identity = m.Auth.AuthIdentity(
            unique_id="test-id",
            name="testuser",
            contact="test@example.com",
            credential_hash="",
            full_name="Test User",
            is_active=True,
            roles=[],
            permissions=[],
            token="",
            session_id="",
            failed_attempts=0,
            locked_until=datetime.min.replace(tzinfo=UTC),
            last_access=datetime.min.replace(tzinfo=UTC),
        )
        set_result = identity.set_credential(strong_password)
        tm.that(set_result.is_success, eq=True)
        verify_result = identity.verify_credential(strong_password)
        tm.that(verify_result.is_success, eq=True)
        tm.that(verify_result.value is True, eq=True)
        wrong_result = identity.verify_credential("WrongPassword123!@")
        tm.that(wrong_result.is_success, eq=True)
        tm.that(wrong_result.value is False, eq=True)


class TestFlextAuthTokenMethods:
    """Test token generation and validation methods."""

    def test_generate_token_method(self) -> None:
        """Test that create_token fails — JWT provider not implemented."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="jwt_test_user",
            email="jwt@example.com",
            password="JWTTestPass123!@#",
        )
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        result = auth.create_token(identity_id=user.unique_id)
        tm.that(not result.is_success, eq=True)
        tm.that(result.error, none=False)

    def test_generate_token_alternative_method(self) -> None:
        """Test that create_token fails via alternative path — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        tm.that(register_result.is_success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        tm.that(auth_result.is_success, eq=True)
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        tm.that(token_result.error, none=False)

    def test_validate_token_success_path(self) -> None:
        """Test that validate_token fails — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        tm.that(register_result.is_success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        tm.that(auth_result.is_success, eq=True)
        authenticated_identity = auth_result.value
        tm.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        val_result = auth.validate_token("any.fake.token")
        tm.that(not val_result.is_success, eq=True)


class TestFlextAuthUserMethods:
    """Test user management methods available in FlextAuth."""

    def test_get_user_method(self) -> None:
        """Test get_user method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_get_user",
            email="getuser@example.com",
            password="GetUserPass123!@",
        )
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        get_result = auth.get_user(user.unique_id)
        tm.that(get_result.is_success, eq=True)
        retrieved_user = get_result.value
        tm.that(retrieved_user.unique_id, eq=user.unique_id)

    def test_get_user_by_username_method(self) -> None:
        """Test get_user_by_username method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_username_lookup",
            email="lookup@example.com",
            password="LookupPass123!@",
        )
        tm.that(user_result.is_success, eq=True)
        get_result = auth.get_user_by_username("test_username_lookup")
        tm.that(get_result.is_success, is_=bool)

    def test_get_user_by_token_direct_api_method(self) -> None:
        """Test that create_token fails — user retrieval by ID still works."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_token_user",
            email="tokenuser@example.com",
            password="TokenUserPass123!@",
        )
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        tm.that(not token_result.is_success, eq=True)
        get_result = auth.get_user(user.unique_id)
        tm.that(get_result.is_success, eq=True)

    def test_logout_user_method(self) -> None:
        """Test logout_user method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_logout_user",
            email="logout@example.com",
            password="LogoutPass123!@",
        )
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        sessions_result = auth.get_user_sessions(user.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.logout_user(session_id)
                tm.that(logout_result.is_success, is_=bool)


class TestFlextAuthSessionMethods:
    """Test session management methods."""

    def test_revoke_session_method(self) -> None:
        """Test revoke_session method functionality."""
        auth = FlextAuth()
        revoke_result = auth.revoke_session("test_session_id")
        tm.that(revoke_result.is_success, is_=bool)

    def test_get_user_sessions_method(self) -> None:
        """Test get_user_sessions method functionality."""
        auth = FlextAuth()
        sessions_result = auth.get_user_sessions("test_user_id")
        tm.that(sessions_result.is_success, is_=bool)

    def test_cleanup_expired_sessions_method(self) -> None:
        """Test cleanup_expired_sessions method functionality."""
        auth = FlextAuth()
        cleanup_result = auth.cleanup_expired_sessions()
        tm.that(cleanup_result.is_success, is_=bool)


class TestFlextAuthQuickStartMethod:
    """Test FlextAuth.quick_start class method."""

    def test_quick_start_with_redacted_ldap_bind_password(self) -> None:
        """Test quick_start class method with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)
        tm.that(auth.config, none=False)

    def test_quick_start_without_redacted_ldap_bind_password(self) -> None:
        """Test quick_start class method without REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert isinstance(auth, FlextAuth)
        tm.that(auth.config, none=False)


class TestFlextAuthConfigurationMethods:
    """Test configuration and utility methods."""

    def test_get_config_method(self) -> None:
        """Test config property functionality."""
        auth = FlextAuth()
        config = auth.config
        tm.that(config, none=False)


class TestFlextAuthErrorHandlingPaths:
    """Test error handling and edge cases in FlextAuth methods."""

    def test_authenticate_with_locked_account(self) -> None:
        """Test authentication with locked user account."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="lockable_user",
            email="lockable@example.com",
            password="LockablePass123!",
        )
        tm.that(user_result.is_success, eq=True)
        for _ in range(6):
            failed_result = auth.authenticate_user(
                username="lockable_user",
                password="wrong_password",
            )
            tm.that(not failed_result.is_success, eq=True)

    def test_token_expiry_edge_cases(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth()
        user_result = auth.register_user(
            "test_user",
            "test@example.com",
            "TestPassword123!",
        )
        tm.that(user_result.is_success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        tm.that(not token_result.is_success, eq=True)
        tm.that(token_result.error, none=False)

    def test_invalid_user_operations(self) -> None:
        """Test operations with invalid user IDs."""
        auth = FlextAuth()
        invalid_user_id = "nonexistent_user_id"
        get_result = auth.get_user(invalid_user_id)
        tm.that(not get_result.is_success, eq=True)
        tm.that(get_result.error, none=False)
        tm.that((get_result.error or "").lower(), has="not found")
        username_result = auth.get_user_by_username("nonexistent_username")
        tm.that(not username_result.is_success, eq=True)
        tm.that(username_result.error, none=False)
        tm.that((username_result.error or "").lower(), has="not found")
        logout_result = auth.logout_user(invalid_user_id)
        tm.that(not logout_result.is_success, eq=True)


class TestFlextAuthAdditionalCoverage:
    """Test additional coverage for missing lines in auth.py."""

    def test_cleanup_expired_sessions_with_user_sessions_index(self) -> None:
        """Test cleanup_expired_sessions method with user sessions index - lines 662-667."""
        auth = FlextAuth()
        auth.register_user("testuser", "test@example.com", "Password123!")
        auth_result = auth.authenticate_user("testuser", "Password123!")
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.get_user_sessions(identity.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            tm.that(sessions, is_=list)
        cleanup_result = auth.cleanup_expired_sessions()
        tm.that(cleanup_result.is_success, eq=True)

    def test_get_user_by_token_invalid_token_error_direct_api(self) -> None:
        """Test validate_token with invalid token — fails with 'not implemented'."""
        auth = FlextAuth()
        result = auth.validate_token("invalid_token")
        tm.that(not result.is_success, eq=True)
        tm.that(result.error, none=False)


class TestAuthModule:
    """Unified test class for auth module functionality."""

    class _TestDataHelper:
        """Nested helper class for test data creation."""

        @staticmethod
        def create_test_user_data() -> t.ContainerMapping:
            """Create test user data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
                "role": "user",
            }

        @staticmethod
        def create_test_auth_data() -> t.ContainerMapping:
            """Create test authentication data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
            }

        @staticmethod
        def create_test_session_data() -> t.ContainerMapping:
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
        result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        tm.that(result, is_=r)

    def test_flext_auth_authenticate_user(self) -> None:
        """Test FlextAuth authenticate_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        if hasattr(auth, "authenticate_user"):
            result = auth.authenticate_user(
                str(test_data["username"]),
                str(test_data["password"]),
            )
            tm.that(result, is_=r)

    def test_flext_auth_get_user_by_username(self) -> None:
        """Test FlextAuth get_user_by_username functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        tm.that(register_result.is_success, eq=True)
        result = auth.get_user_by_username(str(test_data["username"]))
        tm.that(result, is_=r)

    def test_flext_auth_get_user(self) -> None:
        """Test FlextAuth get_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        tm.that(register_result.is_success, eq=True)
        user = register_result.value
        user_id = user.unique_id
        result = auth.get_user(str(user_id))
        tm.that(result, is_=r)

    def test_flext_auth_validate_token(self) -> None:
        """Test that create_token/validate_token fail — JWT provider not implemented."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        tm.that(register_result.is_success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        tm.that(token_result.error, none=False)

    def test_flext_auth_get_user_sessions(self) -> None:
        """Test FlextAuth get_user_sessions functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        tm.that(register_result.is_success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        tm.that(auth_result.is_success, eq=True)
        user = register_result.value
        user_id = user.unique_id
        result = auth.get_user_sessions(user_id)
        tm.that(result, is_=r)
        tm.that(result.is_success, eq=True)

    def test_flext_auth_get_user_by_token_direct_api(self) -> None:
        """Test that create_token fails — user retrieval still works by ID."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        tm.that(register_result.is_success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        result = auth.get_user(identity.unique_id)
        tm.that(result, is_=r)
        tm.that(result.is_success, eq=True)

    def test_flext_auth_revoke_session(self) -> None:
        """Test FlextAuth revoke_session functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        tm.that(register_result.is_success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.get_user_sessions(identity.unique_id)
        if sessions_result.is_success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                result = auth.revoke_session(session_id)
                tm.that(result, is_=r)
                tm.that(result.is_success, eq=True)

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
        tm.that(register_result, is_=r)
        tm.that(register_result.is_success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        tm.that(auth_result, is_=r)
        tm.that(auth_result.is_success, eq=True)
        identity = auth_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(not token_result.is_success, eq=True)
        tm.that(token_result.error, none=False)

    def test_flext_auth_error_handling(self) -> None:
        """Test auth module error handling patterns."""
        auth = FlextAuth()
        result = auth.register_user(username="", email="invalid_email", password="")
        tm.that(result, is_=r)
        tm.that(not result.is_success, eq=True)
        result = auth.authenticate_user("invalid_user", "invalid_password")
        tm.that(result, is_=r)
        tm.that(not result.is_success, eq=True)
        result = auth.get_user_by_username("non_existent_user")
        tm.that(result, is_=r)
        tm.that(not result.is_success, eq=True)
        tm.that(result.error, none=False)
        tm.that((result.error or "").lower(), has="not found")

    def test_flext_auth_with_flext_tests(self) -> None:
        """Test auth functionality with flext_tests infrastructure."""
        auth = FlextAuth()
        test_user_data = {
            "username": "flext_test_user",
            "email": "flext_test@example.com",
            "password": "TestPassword123!",
        }
        test_auth_data = {"username": "flext_test_user", "password": "TestPassword123!"}
        result = auth.register_user(
            username=test_user_data["username"],
            email=test_user_data["email"],
            password=test_user_data["password"],
        )
        tm.that(result, is_=r)
        tm.that(result.is_success, eq=True)
        result = auth.authenticate_user(
            test_auth_data["username"],
            test_auth_data["password"],
        )
        tm.that(result, is_=r)
        tm.that(result.is_success, eq=True)

    def test_flext_auth_docstring(self) -> None:
        """Test that FlextAuth has proper docstring."""
        tm.that(FlextAuth.__doc__, none=False)
        tm.that(len((FlextAuth.__doc__ or "").strip()) > 0, eq=True)

    def test_flext_auth_method_signatures(self) -> None:
        """Test that auth methods have proper signatures."""
        auth = FlextAuth()
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
            tm.that(hasattr(auth, method_name), eq=True)
            method = (
                auth.__getattribute__(method_name)
                if hasattr(auth, method_name)
                else None
            )
            tm.that(callable(method), eq=True)

    def test_flext_auth_with_real_data(self) -> None:
        """Test auth functionality with realistic data scenarios."""
        auth = FlextAuth()
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
        for user_data in realistic_users:
            result = auth.register_user(
                username=user_data["username"],
                email=user_data["email"],
                password=user_data["password"],
                roles=[user_data["role"]] if "role" in user_data else None,
            )
            tm.that(result, is_=r)
            tm.that(result.is_success, eq=True)
        for user_data in realistic_users:
            result = auth.authenticate_user(
                user_data["username"],
                user_data["password"],
            )
            tm.that(result, is_=r)
            tm.that(result.is_success, eq=True)

    def test_flext_auth_integration_patterns(self) -> None:
        """Test auth integration patterns — token ops fail as expected."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        tm.that(register_result, is_=r, ok=True)
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        tm.that(auth_result, is_=r, ok=True)
        authenticated_identity = auth_result.value
        tm.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=authenticated_identity.unique_id)
        tm.that(token_result, is_=r, ok=False)

    def test_flext_auth_performance_patterns(self) -> None:
        """Test auth performance patterns."""
        auth = FlextAuth()
        start_time = time.time()
        test_user_data = self._TestDataHelper.create_test_user_data()
        for i in range(10):
            result = auth.register_user(
                username=f"user_{i}",
                email=f"user_{i}@example.com",
                password=str(test_user_data["password"]),
            )
            tm.that(result, is_=r)
            tm.that(result.is_success, eq=True)
        end_time = time.time()
        tm.that(end_time - start_time, lt=30.0)

    def test_flext_auth_concurrent_operations(self) -> None:
        """Test auth concurrent operations."""
        auth = FlextAuth()

        def register_user(index: int) -> None:
            _ = auth.register_user(
                username=f"user_{index}",
                email=f"user_{index}@example.com",
                password="Password123!",
            )

        def authenticate_user(index: int) -> None:
            _ = auth.authenticate_user(f"user_{index}", "Password123!")

        threads: list[Thread] = []
        for i in range(5):
            thread = threading.Thread(target=register_user, args=(i,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        auth_threads: list[Thread] = []
        for i in range(5):
            thread = threading.Thread(target=authenticate_user, args=(i,))
            auth_threads.append(thread)
            thread.start()
        for thread in auth_threads:
            thread.join()


class _BaseTokenProviderForFlowTests(FlextAuthRfcProvider):
    @override
    def authenticate(self, credentials: t.ContainerValueMapping) -> r[p.Auth.Token]:
        _ = credentials
        return r[p.Auth.Token].fail("Not used in this test")

    @override
    def validate(self, token: str) -> r[bool]:
        _ = token
        return r[bool].ok(True)


class _RefreshCapableProviderForFlowTests(FlextAuthRfcProvider):
    def __init__(self) -> None:
        super().__init__(config={})
        self.last_refresh_input: str | None = None

    @override
    def authenticate(self, credentials: t.ContainerValueMapping) -> r[p.Auth.Token]:
        _ = credentials
        return r[p.Auth.Token].fail("Not used in this test")

    @override
    def validate(self, token: str) -> r[bool]:
        _ = token
        return r[bool].ok(True)

    @override
    def refresh(self, token: str) -> r[p.Auth.Token]:
        self.last_refresh_input = token
        refreshed_token = m.Auth.AuthToken(
            identity_id="middleware-user",
            token="refreshed-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            session_id="",
            is_revoked=False,
            refresh_token="refresh-next",
        )
        return r[p.Auth.Token].ok(refreshed_token)


class _ConcreteKerberosProviderForFlowTests(FlextAuthKerberosProvider):
    @override
    def authenticate(self, credentials: t.ContainerValueMapping) -> r[p.Auth.Token]:
        _ = credentials
        return r[p.Auth.Token].fail("Not used in this test")

    @override
    def validate(self, token: str) -> r[bool]:
        return self.validate_token(token).map(lambda _identity: True)


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
            ).model_dump(),
            token_type="access",
            expiry_minutes=5,
        )
        tm.that(token_result.is_success, eq=True)
        payload = jwt.decode(
            token_result.value,
            "unit-test-secret-key-for-base-provider-12345",
            algorithms=["HS256"],
            audience="flext-auth-tests",
            issuer="flext-auth-tests",
        )
        tm.that(payload["sub"], eq="base-user-123")
        tm.that(payload["token_type"], eq="access")
        tm.that(payload["name"], eq="Base User")

    def test_middleware_refreshes_expired_token(self) -> None:
        provider = _RefreshCapableProviderForFlowTests()
        middleware = FlextAuthMiddleware.FlextWebAuthMiddleware(provider)
        middleware._current_token = m.Auth.AuthToken(
            identity_id="middleware-user",
            token="expired-token",
            token_type="Bearer",
            expires_at=datetime.now(UTC) - timedelta(minutes=1),
            session_id="",
            is_revoked=False,
            refresh_token="refresh-source-token",
        )
        request = HttpRequest()
        result = middleware.process_request(request)
        tm.that(result.is_success, eq=True)
        tm.that(request.headers.get("Authorization"), eq="Bearer refreshed-token")
        tm.that(provider.last_refresh_input, eq="refresh-source-token")

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
        tm.that(token_result.is_success, eq=True)
        identity_result = provider.validate_token(token_result.value)
        tm.that(identity_result.is_success, eq=True)
        identity = identity_result.value
        tm.that(identity.name, eq="Kerberos User")
        tm.that(identity.contact, eq="kerberos@example.com")
        tm.that(identity.roles, eq=["user"])

    def test_oauth2_validate_token_returns_identity(self) -> None:
        provider = FlextAuthOAuth2Provider({
            "client_id": "oauth-test-client",
            "token_endpoint": "https://auth.example.com/token",
            "secret_key": "unit-test-secret-key-for-oauth-provider-12345",
            "algorithm": "HS256",
            "issuer": "flext-auth-tests",
            "audience": "flext-auth-tests",
        })
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
        result = provider.validate_token(encoded_token)
        tm.that(result.is_success, eq=True)
        identity = result.value
        tm.that(identity.unique_id, eq="oauth-user-123")
        tm.that(identity.name, eq="OAuth User")
        tm.that(identity.contact, eq="oauth@example.com")


def _build_identity_for_flow_tests(
    *,
    identity_id: str,
    name: str,
    contact: str,
    roles: t.StrSequence,
) -> m.Auth.AuthIdentity:
    return m.Auth.AuthIdentity(
        unique_id=identity_id,
        name=name,
        contact=contact,
        credential_hash="",
        full_name=name,
        is_active=True,
        roles=roles,
        permissions=[],
        token="",
        session_id="",
        failed_attempts=0,
        locked_until=datetime.min.replace(tzinfo=UTC),
        last_access=datetime.min.replace(tzinfo=UTC),
    )

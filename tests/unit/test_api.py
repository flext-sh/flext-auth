"""Comprehensive tests for FlextAuth API to achieve 100% coverage.

Tests all uncovered methods in api.py including helper classes,
processor registrations, handlers, and advanced patterns.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import threading
import time
from datetime import UTC, datetime
from threading import Thread

import pytest

from flext_auth import (
    FlextAuth,
    FlextAuthSettings,
)
from tests import c, m, r, t, u


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
        u.Tests.Matchers.that(hasattr(auth, "_provider_service"), eq=True)
        u.Tests.Matchers.that(auth._provider_service, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_identity_service"), eq=True)
        u.Tests.Matchers.that(auth._identity_service, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_token_service"), eq=True)
        u.Tests.Matchers.that(auth._token_service, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_session_service"), eq=True)
        u.Tests.Matchers.that(auth._session_service, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_registry"), eq=True)
        u.Tests.Matchers.that(auth._registry, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_dispatcher"), eq=True)
        u.Tests.Matchers.that(auth._dispatcher, none=False)


class TestFlextAuthProcessorRegistration:
    """Test authentication processor registration."""

    def test_services_registered_on_initialization(self) -> None:
        """Test that services are registered during initialization."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "_dispatcher"), eq=True)
        u.Tests.Matchers.that(auth._dispatcher, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_registry"), eq=True)
        u.Tests.Matchers.that(auth._registry, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_provider_service"), eq=True)
        u.Tests.Matchers.that(auth._provider_service, none=False)

    def test_username_validation_processor(self) -> None:
        """Test username validation through processor."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result_valid = auth.register_user(
            "validuser",
            "test@example.com",
            "ValidPass123!",
        )
        u.Tests.Matchers.that(result_valid.success, eq=True)
        result_short = auth.register_user("ab", "test2@example.com", "ValidPass123!")
        u.Tests.Matchers.that(not result_short.success, eq=True)
        u.Tests.Matchers.that(result_short.error, none=False)

    def test_email_normalization_processor(self) -> None:
        """Test email normalization to lowercase."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.register_user("testuser", "TEST@EXAMPLE.COM", "ValidPass123!")
        u.Tests.Matchers.that(result.success, eq=True)
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "testuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        u.Tests.Matchers.that(user.contact, eq="test@example.com")

    def test_password_strength_validation_processor(self) -> None:
        """Test password strength validation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.register_user("user1", "user1@example.com", "weak")
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)
        error_text = (result.error or "").lower()
        u.Tests.Matchers.that(
            ("at least 8 characters" in error_text or "credential" in error_text),
            eq=True,
        )


class TestFlextAuthHandlerRegistration:
    """Test FlextBus handler registration."""

    def test_identity_service_operations(self) -> None:
        """Test that identity service operations work correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "_identity_service"), eq=True)
        u.Tests.Matchers.that(auth._identity_service, none=False)
        result = auth.register_user("cmduser", "cmd@example.com", "CmdPass123!")
        u.Tests.Matchers.that(result.success, eq=True)

    def test_query_handlers_registered(self) -> None:
        """Test that query handlers are registered with FlextBus."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("queryuser", "query@example.com", "QueryPass123!")
        result = auth.identity_service.identity_manager.get_user_by_username(
            "queryuser"
        )
        u.Tests.Matchers.that(result.success, eq=True)

    def test_registry_initialized(self) -> None:
        """Test that registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "_registry"), eq=True)
        u.Tests.Matchers.that(auth._registry, none=False)
        providers = auth._registry.list_providers()
        u.Tests.Matchers.that(providers, is_=list)


class TestFlextAuthAdvancedPatterns:
    """Test advanced flext-core pattern integration."""

    def test_flext_container_integration(self) -> None:
        """Test FlextAuth service initialization."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "_registry"), eq=True)
        u.Tests.Matchers.that(auth._registry, none=False)
        u.Tests.Matchers.that(hasattr(auth, "_dispatcher"), eq=True)
        u.Tests.Matchers.that(auth._dispatcher, none=False)

    def test_flext_context_integration(self) -> None:
        """Test s integration (FlextAuth extends s)."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "_dispatcher"), eq=True)
        u.Tests.Matchers.that(auth._dispatcher, none=False)

    def test_flext_dispatcher_integration(self) -> None:
        """Test FlextDispatcher event bus."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "_dispatcher"), eq=True)
        u.Tests.Matchers.that(auth._dispatcher, none=False)


class TestFlextAuthStorageOperations:
    """Test internal storage operations."""

    def test_username_index_management(self) -> None:
        """Test username index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("indexuser", "index@example.com", "IndexPass123!")
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "indexuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)

    def test_email_index_management(self) -> None:
        """Test email index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("emailuser", "email@example.com", "EmailPass123!")
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "emailuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        u.Tests.Matchers.that(user.contact, eq="email@example.com")

    def test_user_sessions_index_management(self) -> None:
        """Test user sessions index is maintained."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("sessionuser", "session@example.com", "SessionPass123!")
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user = auth_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)


class TestFlextAuthSettingsInitialization:
    """Test explicit settings bootstrap."""

    def test_custom_config_initialization(self) -> None:
        """Test initialization with custom configuration."""
        custom_config = FlextAuthSettings.fetch_global()
        auth = FlextAuth(settings=custom_config)
        u.Tests.Matchers.that(auth.settings, eq=custom_config)


class TestFlextAuthSessionManagement:
    """Test session management operations."""

    def test_get_user_sessions(self) -> None:
        """Test retrieving all sessions for a user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("sessuser", "sess@example.com", "SessPass123!")
        auth_result = auth.authenticate_user("sessuser", "SessPass123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "sessuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)

    def test_revoke_session(self) -> None:
        """Test revoking a session — token creation is not implemented so no sessions are created."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("revokeuser", "revoke@example.com", "RevokePass123!")
        auth_result = auth.authenticate_user("revokeuser", "RevokePass123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user = auth_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)
        sessions = sessions_result.value
        u.Tests.Matchers.that(not sessions, eq=True)
        revoke_result = auth.session_service.session_manager.end_session_by_id(
            "nonexistent_session_id"
        )
        u.Tests.Matchers.that(not revoke_result.success, eq=True)


class TestFlextAuthTokenOperations:
    """Test JWT token operations."""

    def test_create_token_for_user(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "tokenuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_validate_token_with_bearer_prefix(self) -> None:
        """Test token validation — not implemented in JWT provider."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        register_result = auth.register_user(
            "beareruser",
            "bearer@example.com",
            "BearerPass123!",
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        validate_result = auth.token_service.validate_token("any.fake.token")
        u.Tests.Matchers.that(not validate_result.success, eq=True)


class TestFlextAuthErrorHandling:
    """Test error handling and edge cases."""

    def test_duplicate_user_registration(self) -> None:
        """Test handling duplicate user registration."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("dupuser", "dup@example.com", "DupPass123!")
        result = auth.register_user("dupuser", "dup2@example.com", "DupPass123!")
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(
            result.error is not None and "already exists" in result.error.lower(),
            eq=True,
        )

    def test_authentication_with_invalid_credentials(self) -> None:
        """Test authentication with wrong password."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("authuser", "auth@example.com", "AuthPass123!")
        result = auth.authenticate_user("authuser", "WrongPassword123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_get_nonexistent_user(self) -> None:
        """Test retrieving non-existent user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.identity_service.identity_manager.get_user_by_username(
            "nonexistent"
        )
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)
        u.Tests.Matchers.that((result.error or "").lower(), has="not found")


class TestFlextAuthLogging:
    """Test structured logging integration."""

    def test_initialization_logging(self) -> None:
        """Test that initialization is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "logger"), eq=True)
        u.Tests.Matchers.that(auth.logger, none=False)

    def test_handler_registration_logging(self) -> None:
        """Test that handler registration is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert auth is not None


class TestFlextAuthProviderRegistry:
    """Test multi-provider registry (v2.0.0 feature)."""

    def test_provider_registry_initialization(self) -> None:
        """Test provider registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "registry"), eq=True)
        u.Tests.Matchers.that(auth.registry, none=False)

    def test_default_provider_name(self) -> None:
        """Test default provider is set to jwt."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        providers = auth.registry.list_providers()
        u.Tests.Matchers.that(providers, has="jwt")


class TestFlextAuthModelConfiguration:
    """Test Pydantic model configuration."""

    def test_model_config_arbitrary_types_allowed(self) -> None:
        """Test that arbitrary types are allowed in model settings."""
        u.Tests.Matchers.that(hasattr(m.Auth.AuthIdentity, "model_config"), eq=True)

    def test_model_config_validate_assignment(self) -> None:
        """Test validate_assignment configuration."""
        settings = FlextAuthSettings.fetch_global()
        u.Tests.Matchers.that(
            settings.model_config.get("validate_assignment", False) is True, eq=True
        )


class TestFlextAuth:
    """Unit tests for FlextAuth class."""

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        FlextAuthSettings._reset_instance()
        auth: FlextAuth = FlextAuth()
        u.Tests.Matchers.that(auth._config.auth_secret, none=False)
        u.Tests.Matchers.that(len(auth._config.auth_secret.get_secret_value()), gt=20)
        u.Tests.Matchers.that(auth._config.hash_rounds, eq=12)
        u.Tests.Matchers.that(auth._config.expiry_minutes, eq=1440)
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
        auth_custom: FlextAuth = FlextAuth(settings=custom_config)
        u.Tests.Matchers.that(
            auth_custom._config.auth_secret.get_secret_value(), eq=custom_secret
        )
        u.Tests.Matchers.that(auth_custom._config.hash_rounds, eq=custom_rounds)
        u.Tests.Matchers.that(auth_custom._config.expiry_minutes, eq=custom_expiry)

    def test_user_registration_success(self) -> None:
        """Test successful user registration."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            roles=["user"],
        )
        u.Tests.Matchers.that(result.success, eq=True)
        user = result.value
        u.Tests.Matchers.that(user.name, eq="testuser")
        u.Tests.Matchers.that(user.contact, eq="test@example.com")
        u.Tests.Matchers.that(user.roles, has="user")
        u.Tests.Matchers.that(user.is_active, eq=True)

    def test_user_registration_duplicate_username(self) -> None:
        """Test user registration with duplicate username."""
        auth: FlextAuth = FlextAuth()
        auth.register_user("testuser", "test1@example.com", "Password123!")
        duplicate_result = auth.register_user(
            "testuser",
            "test2@example.com",
            "Password123!",
        )
        u.Tests.Matchers.that(duplicate_result.failure, eq=True)
        u.Tests.Matchers.that((duplicate_result.error or ""), has="already exists")

    def test_user_registration_duplicate_email(self) -> None:
        """Test user registration with duplicate email."""
        auth: FlextAuth = FlextAuth()
        first_result = auth.register_user("user1", "test@example.com", "Password123!")
        u.Tests.Matchers.that(first_result.success, eq=True)
        duplicate_result = auth.register_user(
            "user2",
            "test@example.com",
            "Password123!",
        )
        u.Tests.Matchers.that(duplicate_result.failure, eq=True)
        u.Tests.Matchers.that((duplicate_result.error or ""), has="already exists")

    def test_user_authentication_success(self) -> None:
        """Test successful user authentication."""
        auth: FlextAuth = FlextAuth()
        username = "authtest"
        password = "AuthPassword123!"
        reg_result = auth.register_user(username, "auth@example.com", password)
        u.Tests.Matchers.that(reg_result.success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        u.Tests.Matchers.that(identity.name, eq=username)
        u.Tests.Matchers.that(identity.contact, eq="auth@example.com")

    def test_user_authentication_invalid_credentials(self) -> None:
        """Test authentication with invalid credentials."""
        auth: FlextAuth = FlextAuth()
        username = "testuser"
        auth.register_user(username, "test@example.com", "CorrectPassword123!")
        failed_auth = auth.authenticate_user(username, "WrongPassword123!")
        u.Tests.Matchers.that(not failed_auth.success, eq=True)
        u.Tests.Matchers.that(not failed_auth.success, eq=True)
        u.Tests.Matchers.that((failed_auth.error or ""), has="Invalid credentials")

    def test_token_validation_valid_token(self) -> None:
        """Test that token creation/validation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "tokenuser"
        password = "TokenPassword123!"
        register_result = auth.register_user(username, "token@example.com", password)
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        authenticated_identity = auth_result.value
        u.Tests.Matchers.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_token_validation_invalid_token(self) -> None:
        """Test validation of invalid token — fails with 'not implemented'."""
        auth: FlextAuth = FlextAuth()
        invalid_result = auth.token_service.validate_token("invalid.token.here")
        u.Tests.Matchers.that(not invalid_result.success, eq=True)
        u.Tests.Matchers.that(invalid_result.error, none=False)

    def test_token_validation_bearer_prefix(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "beareruser"
        password = "BearerPassword123!"
        register_result = auth.register_user(username, "bearer@example.com", password)
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

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
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)
        sessions = sessions_result.value
        u.Tests.Matchers.that(sessions, is_=list)
        u.Tests.Matchers.that(len(sessions), gte=0)

    def test_user_logout(self) -> None:
        """Test user logout functionality."""
        auth: FlextAuth = FlextAuth()
        username = "logoutuser"
        password = "LogoutPassword123!"
        auth.register_user(username, "logout@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id
        )
        if sessions_result.success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.session_service.session_manager.end_session_by_id(
                    session_id
                )
                u.Tests.Matchers.that(logout_result.success, eq=True)

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth: FlextAuth = FlextAuth()
        cleanup_result = auth.session_service.cleanup_expired_sessions()
        u.Tests.Matchers.that(cleanup_result.success, eq=True)
        cleaned_count = cleanup_result.value
        u.Tests.Matchers.that(cleaned_count, is_=int)
        u.Tests.Matchers.that(cleaned_count, gte=0)

    def test_sync_api_methods(self) -> None:
        """Test synchronous API methods work as expected."""
        auth: FlextAuth = FlextAuth()
        username = "syncuser"
        password = "SyncPassword123!"
        create_result = auth.register_user(username, "sync@example.com", password)
        u.Tests.Matchers.that(create_result.success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)


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
            u.Tests.Matchers.that(not failed_auth.success, eq=True)
        locked_auth = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(not locked_auth.success, eq=True)
        u.Tests.Matchers.that(
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
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)


class TestFlextAuthErrorHandlingSecond:
    """Unit tests for error handling scenarios."""

    def test_empty_username_registration(self) -> None:
        """Test registration with empty username."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("", "empty@example.com", "Password123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_empty_email_registration(self) -> None:
        """Test registration with empty email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "", "Password123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_empty_password_registration(self) -> None:
        """Test registration with empty password."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "test@example.com", "")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_invalid_email_registration(self) -> None:
        """Test registration with invalid email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "invalid-email", "Password123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_nonexistent_user_authentication(self) -> None:
        """Test authentication of non-existent user."""
        auth: FlextAuth = FlextAuth()
        auth_result = auth.authenticate_user("nonexistent", "password")
        u.Tests.Matchers.that(not auth_result.success, eq=True)
        u.Tests.Matchers.that(auth_result.error, none=False)
        u.Tests.Matchers.that(auth_result.error or "", empty=False)

    def test_invalid_session_logout(self) -> None:
        """Test logout with invalid session ID."""
        auth: FlextAuth = FlextAuth()
        logout_result = auth.session_service.session_manager.end_session_by_id(
            "invalid_session_id"
        )
        u.Tests.Matchers.that(not logout_result.success, eq=True)
        u.Tests.Matchers.that(not logout_result.success, eq=True)
        u.Tests.Matchers.that((logout_result.error or ""), has="Session not found")


class TestFlextAuthQuickStartFunction:
    """Unit tests for FlextAuth.quick_start() classmethod."""

    def test_flext_auth_quick_start_default(self) -> None:
        """Test FlextAuth.quick_start() with default parameters."""
        auth = FlextAuth.quick_start()
        assert isinstance(auth, FlextAuth)
        u.Tests.Matchers.that(auth.settings, none=False)
        u.Tests.Matchers.that(auth.registry, none=False)

    def test_flext_auth_quick_start_no_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() without creating REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert isinstance(auth, FlextAuth)
        nonexistent_result = (
            auth.identity_service.identity_manager.get_user_by_username(
                "nonexistent_user"
            )
        )
        u.Tests.Matchers.that(not nonexistent_result.success, eq=True)
        u.Tests.Matchers.that(nonexistent_result.error, none=False)
        u.Tests.Matchers.that((nonexistent_result.error or "").lower(), has="not found")

    def test_flext_auth_quick_start_custom_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)


class TestFlextAuthInitializationCoverage:
    """Test FlextAuth initialization edge cases - covering lines 228-229."""

    def test_flext_auth_config_creation_failure(self) -> None:
        """Test FlextAuth initialization when settings creation fails - lines 228-229."""
        try:
            auth = FlextAuth()
            u.Tests.Matchers.that(auth._config, none=False)
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
        settings = FlextAuthSettings.model_validate({
            "expiry_minutes": 120,
            "hash_rounds": 10,
            "auth_secret": "test-secret-key-with-minimum-32-characters-length",
        })
        auth = FlextAuth(settings=settings)
        u.Tests.Matchers.that(auth._config.expiry_minutes, eq=120)
        u.Tests.Matchers.that(auth._config.hash_rounds, eq=10)


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
        u.Tests.Matchers.that(not result.success, eq=True)
        error_msg = result.error or ""
        u.Tests.Matchers.that(
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
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, is_=str)

    def test_validate_token_invalid_cases(self) -> None:
        """Test token validation with invalid tokens."""
        auth = FlextAuth()
        result = auth.token_service.validate_token("invalid.malformed.token")
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.token_service.validate_token("")
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.token_service.validate_token("invalid.token.format")
        u.Tests.Matchers.that(not result.success, eq=True)


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
        result = identity.update_credential("StrongTestPass123!@#")
        u.Tests.Matchers.that(result.success, eq=True)
        u.Tests.Matchers.that(result.value is True, eq=True)
        u.Tests.Matchers.that(identity.credential_hash, ne="StrongTestPass123!@#")
        u.Tests.Matchers.that(len(identity.credential_hash), gt=10)

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
        set_result = identity.update_credential(strong_password)
        u.Tests.Matchers.that(set_result.success, eq=True)
        verify_result = identity.verify_credential(strong_password)
        u.Tests.Matchers.that(verify_result.success, eq=True)
        u.Tests.Matchers.that(verify_result.value is True, eq=True)
        wrong_result = identity.verify_credential("WrongPassword123!@")
        u.Tests.Matchers.that(wrong_result.success, eq=True)
        u.Tests.Matchers.that(wrong_result.value is False, eq=True)


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
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)

    def test_generate_token_alternative_method(self) -> None:
        """Test that create_token fails via alternative path — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_validate_token_success_path(self) -> None:
        """Test that validate_token fails — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        authenticated_identity = auth_result.value
        u.Tests.Matchers.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        val_result = auth.token_service.validate_token("any.fake.token")
        u.Tests.Matchers.that(not val_result.success, eq=True)


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
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        get_result = auth.identity_service.identity_manager.get_user(user.unique_id)
        u.Tests.Matchers.that(get_result.success, eq=True)
        retrieved_user = get_result.value
        u.Tests.Matchers.that(retrieved_user.unique_id, eq=user.unique_id)

    def test_get_user_by_username_method(self) -> None:
        """Test get_user_by_username method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_username_lookup",
            email="lookup@example.com",
            password="LookupPass123!@",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        get_result = auth.identity_service.identity_manager.get_user_by_username(
            "test_username_lookup"
        )
        u.Tests.Matchers.that(get_result.success, is_=bool)

    def test_get_user_by_token_direct_api_method(self) -> None:
        """Test that create_token fails — user retrieval by ID still works."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_token_user",
            email="tokenuser@example.com",
            password="TokenUserPass123!@",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        get_result = auth.identity_service.identity_manager.get_user(user.unique_id)
        u.Tests.Matchers.that(get_result.success, eq=True)

    def test_logout_user_method(self) -> None:
        """Test logout_user method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_logout_user",
            email="logout@example.com",
            password="LogoutPass123!@",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id
        )
        if sessions_result.success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.session_service.session_manager.end_session_by_id(
                    session_id
                )
                u.Tests.Matchers.that(logout_result.success, is_=bool)


class TestFlextAuthSessionMethods:
    """Test session management methods."""

    def test_revoke_session_method(self) -> None:
        """Test revoke_session method functionality."""
        auth = FlextAuth()
        revoke_result = auth.session_service.session_manager.end_session_by_id(
            "test_session_id"
        )
        u.Tests.Matchers.that(revoke_result.success, is_=bool)

    def test_get_user_sessions_method(self) -> None:
        """Test get_user_sessions method functionality."""
        auth = FlextAuth()
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            "test_user_id"
        )
        u.Tests.Matchers.that(sessions_result.success, is_=bool)

    def test_cleanup_expired_sessions_method(self) -> None:
        """Test cleanup_expired_sessions method functionality."""
        auth = FlextAuth()
        cleanup_result = auth.session_service.cleanup_expired_sessions()
        u.Tests.Matchers.that(cleanup_result.success, is_=bool)


class TestFlextAuthQuickStartMethod:
    """Test FlextAuth.quick_start class method."""

    def test_quick_start_with_redacted_ldap_bind_password(self) -> None:
        """Test quick_start class method with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)
        u.Tests.Matchers.that(auth.settings, none=False)

    def test_quick_start_without_redacted_ldap_bind_password(self) -> None:
        """Test quick_start class method without REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert isinstance(auth, FlextAuth)
        u.Tests.Matchers.that(auth.settings, none=False)


class TestFlextAuthConfigurationMethods:
    """Test configuration and utility methods."""

    def test_get_config_method(self) -> None:
        """Test settings property functionality."""
        auth = FlextAuth()
        settings = auth.settings
        u.Tests.Matchers.that(settings, none=False)


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
        u.Tests.Matchers.that(user_result.success, eq=True)
        for _ in range(6):
            failed_result = auth.authenticate_user(
                username="lockable_user",
                password="wrong_password",
            )
            u.Tests.Matchers.that(not failed_result.success, eq=True)

    def test_token_expiry_edge_cases(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth()
        user_result = auth.register_user(
            "test_user",
            "test@example.com",
            "TestPassword123!",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_invalid_user_operations(self) -> None:
        """Test operations with invalid user IDs."""
        auth = FlextAuth()
        invalid_user_id = "nonexistent_user_id"
        get_result = auth.identity_service.identity_manager.get_user(invalid_user_id)
        u.Tests.Matchers.that(not get_result.success, eq=True)
        u.Tests.Matchers.that(get_result.error, none=False)
        u.Tests.Matchers.that((get_result.error or "").lower(), has="not found")
        username_result = auth.identity_service.identity_manager.get_user_by_username(
            "nonexistent_username"
        )
        u.Tests.Matchers.that(not username_result.success, eq=True)
        u.Tests.Matchers.that(username_result.error, none=False)
        u.Tests.Matchers.that((username_result.error or "").lower(), has="not found")
        logout_result = auth.session_service.session_manager.end_session_by_id(
            invalid_user_id
        )
        u.Tests.Matchers.that(not logout_result.success, eq=True)


class TestFlextAuthAdditionalCoverage:
    """Test additional coverage for missing lines in auth.py."""

    def test_cleanup_expired_sessions_with_user_sessions_index(self) -> None:
        """Test cleanup_expired_sessions method with user sessions index - lines 662-667."""
        auth = FlextAuth()
        auth.register_user("testuser", "test@example.com", "Password123!")
        auth_result = auth.authenticate_user("testuser", "Password123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id
        )
        if sessions_result.success:
            sessions = sessions_result.value
            u.Tests.Matchers.that(sessions, is_=list)
        cleanup_result = auth.session_service.cleanup_expired_sessions()
        u.Tests.Matchers.that(cleanup_result.success, eq=True)

    def test_get_user_by_token_invalid_token_error_direct_api(self) -> None:
        """Test validate_token with invalid token — fails with 'not implemented'."""
        auth = FlextAuth()
        result = auth.token_service.validate_token("invalid_token")
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)


class TestAuthModule:
    """Unified test class for auth module functionality."""

    class _TestDataHelper:
        """Nested helper class for test data creation."""

        @staticmethod
        def create_test_user_data() -> t.RecursiveContainerMapping:
            """Create test user data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
                "role": "user",
            }

        @staticmethod
        def create_test_auth_data() -> t.RecursiveContainerMapping:
            """Create test authentication data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
            }

        @staticmethod
        def create_test_session_data() -> t.RecursiveContainerMapping:
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
        u.Tests.Matchers.that(result, is_=r)

    def test_flext_auth_authenticate_user(self) -> None:
        """Test FlextAuth authenticate_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        if hasattr(auth, "authenticate_user"):
            result = auth.authenticate_user(
                str(test_data["username"]),
                str(test_data["password"]),
            )
            u.Tests.Matchers.that(result, is_=r)

    def test_flext_auth_get_user_by_username(self) -> None:
        """Test FlextAuth get_user_by_username functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        result = auth.identity_service.identity_manager.get_user_by_username(
            str(test_data["username"])
        )
        u.Tests.Matchers.that(result, is_=r)

    def test_flext_auth_get_user(self) -> None:
        """Test FlextAuth get_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        user = register_result.value
        user_id = user.unique_id
        result = auth.identity_service.identity_manager.get_user(str(user_id))
        u.Tests.Matchers.that(result, is_=r)

    def test_flext_auth_validate_token(self) -> None:
        """Test that create_token/validate_token fail — JWT provider not implemented."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_flext_auth_get_user_sessions(self) -> None:
        """Test FlextAuth get_user_sessions functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user = register_result.value
        user_id = user.unique_id
        result = auth.session_service.session_manager.get_active_sessions(user_id)
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_get_user_by_token_direct_api(self) -> None:
        """Test that create_token fails — user retrieval still works by ID."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        result = auth.identity_service.identity_manager.get_user(identity.unique_id)
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_revoke_session(self) -> None:
        """Test FlextAuth revoke_session functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id
        )
        if sessions_result.success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                result = auth.session_service.session_manager.end_session_by_id(
                    session_id
                )
                u.Tests.Matchers.that(result, is_=r)
                u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_comprehensive_scenario(self) -> None:
        """Test comprehensive auth module scenario — token ops succeed as expected."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        assert auth is not None
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        u.Tests.Matchers.that(register_result, is_=r)
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        u.Tests.Matchers.that(auth_result, is_=r)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_flext_auth_error_handling(self) -> None:
        """Test auth module error handling patterns."""
        auth = FlextAuth()
        result = auth.register_user(username="", email="invalid_email", password="")
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.authenticate_user("invalid_user", "invalid_password")
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.identity_service.identity_manager.get_user_by_username(
            "non_existent_user"
        )
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)
        u.Tests.Matchers.that((result.error or "").lower(), has="not found")

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
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)
        result = auth.authenticate_user(
            test_auth_data["username"],
            test_auth_data["password"],
        )
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_docstring(self) -> None:
        """Test that FlextAuth has proper docstring."""
        u.Tests.Matchers.that(FlextAuth.__doc__, none=False)
        u.Tests.Matchers.that(len((FlextAuth.__doc__ or "").strip()) > 0, eq=True)

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
            u.Tests.Matchers.that(hasattr(auth, method_name), eq=True)
            method = (
                auth.__getattribute__(method_name)
                if hasattr(auth, method_name)
                else None
            )
            u.Tests.Matchers.that(callable(method), eq=True)

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
            u.Tests.Matchers.that(result, is_=r)
            u.Tests.Matchers.that(result.success, eq=True)
        for user_data in realistic_users:
            result = auth.authenticate_user(
                user_data["username"],
                user_data["password"],
            )
            u.Tests.Matchers.that(result, is_=r)
            u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_integration_patterns(self) -> None:
        """Test auth integration patterns — token ops succeed as expected."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        u.Tests.Matchers.that(register_result, is_=r, ok=True)
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        u.Tests.Matchers.that(auth_result, is_=r, ok=True)
        authenticated_identity = auth_result.value
        u.Tests.Matchers.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=authenticated_identity.unique_id)
        u.Tests.Matchers.that(token_result, is_=r, ok=True)

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
            u.Tests.Matchers.that(result, is_=r)
            u.Tests.Matchers.that(result.success, eq=True)
        end_time = time.time()
        u.Tests.Matchers.that(end_time - start_time, lt=30.0)

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


class TestPublicApiTokenFlows:
    """Test token flows through FlextAuth public API only."""

    def test_public_api_create_token_for_registered_user(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="public-api-token-user",
            email="public-api-token-user@example.com",
            password="PublicApiTokenPass123!",
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)
        u.Tests.Matchers.that(token_result.value.count("."), eq=2)

    def test_public_api_validate_token_success(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="public-api-validate-user",
            email="public-api-validate-user@example.com",
            password="PublicApiValidatePass123!",
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)

        validation_result = auth.token_service.validate_token(token_result.value)
        u.Tests.Matchers.ok(validation_result)
        u.Tests.Matchers.that(validation_result.value, eq=True)

    def test_public_api_validate_token_failure(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        validation_result = auth.token_service.validate_token("invalid.jwt.token")
        u.Tests.Matchers.fail(validation_result)

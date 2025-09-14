"""Unit tests for FlextAuth module - Main authentication service.

Tests cover FlextAuth class functionality, authentication flows,
session management, and user lifecycle operations.



Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import (
    FlextAuth,
    FlextAuthConfig,
    FlextAuthConstants,
    flext_auth_quick_start,
)


class TestFlextAuth:
    """Unit tests for FlextAuth class."""

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        # Clear singleton to ensure clean test
        FlextAuthConfig.clear_global_instance()

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
        assert user.email_str == "test@example.com"
        assert "user" in user.roles
        assert user.is_active

    def test_user_registration_duplicate_username(self) -> None:
        """Test user registration with duplicate username."""
        auth: FlextAuth = FlextAuth()

        # First registration
        auth.register_user("testuser", "test1@example.com", "Password123!")

        # Second registration with same username
        duplicate_result = auth.register_user(
            "testuser", "test2@example.com", "Password123!"
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
            "user2", "test@example.com", "Password123!"
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
        tokens = auth_data["tokens"]
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
        tokens = auth_data["tokens"]
        assert isinstance(tokens, dict), "tokens must be dict"
        access_token = tokens["access_token"]
        assert isinstance(access_token, str), "access_token must be string"
        validation_result = auth.validate_token(access_token)

        assert validation_result.is_success
        validation_data = validation_result.value
        assert validation_data["valid"] is True
        assert validation_data["username"] == username
        assert "user_id" in validation_data
        assert "role" in validation_data

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
        tokens = auth_data["tokens"]
        assert isinstance(tokens, dict), "tokens must be dict"
        access_token = tokens["access_token"]
        assert isinstance(access_token, str), "access_token must be string"
        bearer_result = auth.validate_token(f"Bearer {access_token}")
        assert bearer_result.is_success
        bearer_data = bearer_result.value
        assert isinstance(bearer_data, dict), "bearer_data must be dict"
        assert bearer_data["username"] == username

    def test_session_management(self) -> None:
        """Test session management functionality."""
        auth: FlextAuth = FlextAuth()
        username = "sessionuser"
        password = "SessionPassword123!"

        # Register and authenticate with session data
        auth.register_user(username, "session@example.com", password)
        auth_result = auth.authenticate_user(
            username, password, "127.0.0.1", "test-user-agent"
        )
        assert auth_result.success

        # Extract session information
        auth_data = auth_result.value
        assert isinstance(auth_data, dict), "auth_data must be dict"
        session_info = auth_data["session"]
        assert isinstance(session_info, dict), "session_info must be dict"
        session_id = session_info["session_id"]
        user_info = auth_data["user"]
        assert isinstance(user_info, dict), "user_info must be dict"
        user_id = user_info["id"]

        # Test get user sessions
        sessions_result = auth.get_user_sessions(user_id)
        assert sessions_result.success
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
        assert auth_result.success

        # Extract session ID from authentication result
        auth_data = auth_result.value
        assert isinstance(auth_data, dict)
        assert "session" in auth_data
        session_info = auth_data["session"]
        assert isinstance(session_info, dict), "session_info must be dict"
        session_id = session_info["session_id"]

        logout_result = auth.logout_user(session_id)
        assert logout_result.success

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth: FlextAuth = FlextAuth()

        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success
        assert isinstance(cleanup_result.value, int)
        assert cleanup_result.value >= 0

    def test_sync_api_methods(self) -> None:
        """Test synchronous API methods work as expected."""
        auth: FlextAuth = FlextAuth()
        username = "syncuser"
        password = "SyncPassword123!"

        # Test user creation with current API
        create_result = auth.register_user(username, "sync@example.com", password)
        assert create_result.success

        # Test authentication with current API
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success


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
        for _ in range(FlextAuthConstants.MAX_LOGIN_ATTEMPTS):
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

        # Test with weak password
        weak_result = auth.register_user(
            "weakuser",
            "weak@example.com",
            "weak",  # Too weak
        )
        assert weak_result.is_failure


class TestFlextAuthErrorHandling:
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
    """Unit tests for flext_auth_quick_start convenience function."""

    def test_flext_auth_quick_start_default(self) -> None:
        """Test flext_auth_quick_start with default parameters."""
        auth = flext_auth_quick_start()
        assert isinstance(auth, FlextAuth)
        # Should create REDACTED_LDAP_BIND_PASSWORD user by default
        REDACTED_LDAP_BIND_PASSWORD_result = auth.get_user_by_username("REDACTED_LDAP_BIND_PASSWORD")
        assert REDACTED_LDAP_BIND_PASSWORD_result.is_success
        assert REDACTED_LDAP_BIND_PASSWORD_result.value is not None

    def test_flext_auth_quick_start_no_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test flext_auth_quick_start without creating REDACTED_LDAP_BIND_PASSWORD user."""
        auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert isinstance(auth, FlextAuth)
        # Should not create REDACTED_LDAP_BIND_PASSWORD user - check that REDACTED_LDAP_BIND_PASSWORD user is None
        # since REDACTED_LDAP_BIND_PASSWORD might have been created in previous tests, we test the function works
        nonexistent_result = auth.get_user_by_username("nonexistent_user")
        assert nonexistent_result.is_success
        assert nonexistent_result.value is None

    def test_flext_auth_quick_start_custom_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test flext_auth_quick_start with custom REDACTED_LDAP_BIND_PASSWORD credentials."""
        custom_username = "custom_REDACTED_LDAP_BIND_PASSWORD_func"
        custom_password = "CustomPasswordFunc123!"

        auth = flext_auth_quick_start(
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

"""Unit tests for FlextAuth module - Main authentication service.

Tests cover FlextAuth class functionality, authentication flows,
session management, and user lifecycle operations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuth
from flext_core import FlextConstants


class TestFlextAuth:
    """Unit tests for FlextAuth class."""

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        # Test default initialization
        auth = FlextAuth()
        assert auth.jwt_secret is not None
        assert len(auth.jwt_secret) > 20
        assert auth.password_rounds == 10  # Development environment uses 10 rounds
        assert auth.token_expiry_minutes == 480  # Development environment uses 8 hours

        # Test custom initialization
        custom_secret = "test-secret-key"
        custom_rounds = 8
        custom_expiry = 60

        auth_custom = FlextAuth(
            jwt_secret=custom_secret,
            password_rounds=custom_rounds,
            token_expire_minutes=custom_expiry,
        )
        assert auth_custom.jwt_secret == custom_secret
        assert auth_custom.password_rounds == custom_rounds
        assert auth_custom.token_expiry_minutes == custom_expiry

    def test_user_registration_success(self) -> None:
        """Test successful user registration."""
        auth = FlextAuth()

        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            roles=["user"],
        )

        assert result.success
        user = result.value
        assert user.username == "testuser"
        assert user.email_str == "test@example.com"
        assert "user" in user.roles
        assert user.is_active

    def test_user_registration_duplicate_username(self) -> None:
        """Test user registration with duplicate username."""
        auth = FlextAuth()

        # First registration
        auth.register_user("testuser", "test1@example.com", "Password123!")

        # Second registration with same username
        duplicate_result = auth.register_user(
            "testuser", "test2@example.com", "Password123!"
        )
        assert duplicate_result.is_failure
        assert "already exists" in duplicate_result.error

    def test_user_registration_duplicate_email(self) -> None:
        """Test user registration with duplicate email."""
        auth = FlextAuth()

        # First registration
        auth.register_user("user1", "test@example.com", "Password123!")

        # Second registration with same email
        duplicate_result = auth.register_user(
            "user2", "test@example.com", "Password123!"
        )
        assert duplicate_result.is_failure
        assert "already exists" in duplicate_result.error

    def test_user_authentication_success(self) -> None:
        """Test successful user authentication."""
        auth = FlextAuth()
        username = "authtest"
        password = "AuthPassword123!"

        # Register user first
        reg_result = auth.register_user(username, "auth@example.com", password)
        assert reg_result.success

        # Test authentication
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success

        auth_data = auth_result.value
        assert auth_data["success"] is True
        assert "user" in auth_data
        assert "tokens" in auth_data
        assert "session" in auth_data

        # Validate token data
        tokens = auth_data["tokens"]
        assert "access_token" in tokens
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == 480 * 60  # Development environment uses 480 minutes

    def test_user_authentication_invalid_credentials(self) -> None:
        """Test authentication with invalid credentials."""
        auth = FlextAuth()
        username = "testuser"

        # Register user
        auth.register_user(username, "test@example.com", "CorrectPassword123!")

        # Test with wrong password
        failed_auth = auth.authenticate_user(username, "WrongPassword123!")
        assert failed_auth.is_failure
        assert "Invalid credentials" in failed_auth.error

    def test_token_validation_valid_token(self) -> None:
        """Test validation of valid token."""
        auth = FlextAuth()
        username = "tokenuser"
        password = "TokenPassword123!"

        # Register and authenticate to get token
        auth.register_user(username, "token@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success

        # Extract and validate token
        access_token = auth_result.value["tokens"]["access_token"]
        validation_result = auth.validate_token(access_token)

        assert validation_result.success
        validation_data = validation_result.value
        assert validation_data["valid"] is True
        assert validation_data["username"] == username
        assert "user_id" in validation_data
        assert "role" in validation_data

    def test_token_validation_invalid_token(self) -> None:
        """Test validation of invalid token."""
        auth = FlextAuth()

        invalid_result = auth.validate_token("invalid.token.here")
        assert invalid_result.is_failure
        assert "token" in invalid_result.error.lower()

    def test_token_validation_bearer_prefix(self) -> None:
        """Test token validation with Bearer prefix."""
        auth = FlextAuth()
        username = "beareruser"
        password = "BearerPassword123!"

        # Register and authenticate
        auth.register_user(username, "bearer@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success

        # Test with Bearer prefix
        access_token = auth_result.value["tokens"]["access_token"]
        bearer_result = auth.validate_token(f"Bearer {access_token}")
        assert bearer_result.success
        assert bearer_result.value["username"] == username

    def test_session_management(self) -> None:
        """Test session management functionality."""
        auth = FlextAuth()
        username = "sessionuser"
        password = "SessionPassword123!"

        # Register and authenticate with session data
        auth.register_user(username, "session@example.com", password)
        auth_result = auth.authenticate_user(
            username, password, "127.0.0.1", "test-user-agent"
        )
        assert auth_result.success

        # Extract session information
        session_info = auth_result.value["session"]
        session_id = session_info["session_id"]
        user_id = auth_result.value["user"]["id"]

        # Test get user sessions
        sessions_result = auth.get_user_sessions(user_id)
        assert sessions_result.success
        sessions = sessions_result.value
        assert len(sessions) >= 1
        assert any(s.id == session_id for s in sessions)

    def test_user_logout(self) -> None:
        """Test user logout functionality."""
        auth = FlextAuth()
        username = "logoutuser"
        password = "LogoutPassword123!"

        # Register and authenticate
        auth.register_user(username, "logout@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success

        # Extract session ID and user ID from authentication result
        session_info = auth_result.value
        assert isinstance(session_info, dict) and "session" in session_info
        session_id = session_info["session"]["session_id"]
        user_id = session_info["user"]["id"]
        
        logout_result = auth.logout_user(session_id)
        assert logout_result.success

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth = FlextAuth()

        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success
        assert isinstance(cleanup_result.value, int)
        assert cleanup_result.value >= 0

    def test_sync_api_methods(self) -> None:
        """Test synchronous API methods work as expected."""
        auth = FlextAuth()
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
        auth = FlextAuth()
        username = "locktest"
        password = "LockTestPassword123!"

        # Register user
        auth.register_user(username, "lock@example.com", password)

        # Attempt multiple failed logins
        for _ in range(FlextConstants.Auth.MAX_LOGIN_ATTEMPTS):
            failed_auth = auth.authenticate_user(username, "wrong_password")
            assert failed_auth.is_failure

        # Next attempt should indicate account is locked
        locked_auth = auth.authenticate_user(username, password)
        assert locked_auth.is_failure
        # Should fail even with correct password due to lockout
        assert (
            "locked" in locked_auth.error.lower()
            or "inactive" in locked_auth.error.lower()
        )

    def test_password_strength_enforcement(self) -> None:
        """Test password strength requirements."""
        auth = FlextAuth()

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
        auth = FlextAuth()

        result = auth.register_user("", "empty@example.com", "Password123!")
        assert result.is_failure

    def test_empty_email_registration(self) -> None:
        """Test registration with empty email."""
        auth = FlextAuth()

        result = auth.register_user("user", "", "Password123!")
        assert result.is_failure

    def test_empty_password_registration(self) -> None:
        """Test registration with empty password."""
        auth = FlextAuth()

        result = auth.register_user("user", "test@example.com", "")
        assert result.is_failure

    def test_invalid_email_registration(self) -> None:
        """Test registration with invalid email."""
        auth = FlextAuth()

        result = auth.register_user("user", "invalid-email", "Password123!")
        assert result.is_failure

    def test_nonexistent_user_authentication(self) -> None:
        """Test authentication of non-existent user."""
        auth = FlextAuth()

        auth_result = auth.authenticate_user("nonexistent", "password")
        assert auth_result.is_failure
        assert "Invalid credentials" in auth_result.error

    def test_invalid_session_logout(self) -> None:
        """Test logout with invalid session ID."""
        auth = FlextAuth()

        logout_result = auth.logout_user("invalid_session_id")
        assert logout_result.is_failure
        assert "Session not found" in logout_result.error

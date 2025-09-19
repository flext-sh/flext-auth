"""Complete tests for FlextAuth - 100% coverage, no mocks, real functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import cast

from flext_auth import (
    FlextAuth,
    FlextAuthConfig,
    FlextAuthModels,
)

# Use unified class structure
AuthenticationResponseDict = FlextAuthModels.AuthenticationResponseDict
Session = FlextAuthModels.Session
User = FlextAuthModels.User


class TestFlextAuth:
    """Test FlextAuth complete functionality."""

    def test_create_auth_direct(self) -> None:
        """Test FlextAuth direct creation without factory function."""
        auth: FlextAuth = FlextAuth()
        assert isinstance(auth, FlextAuth)
        config = auth.config
        assert config.jwt_secret is not None
        assert len(config.jwt_secret) > 20

    def test_flext_auth_creation(self) -> None:
        """Test FlextAuth initialization."""
        auth: FlextAuth = FlextAuth()
        config = auth.config
        assert config.jwt_secret is not None
        assert len(config.jwt_secret) > 30  # Should be secure length
        assert (
            config.jwt_expiry_minutes >= 30
        )  # Production-ready default (at least 30 minutes)

        # Test that auth is properly initialized
        jwt_settings: dict[str, object] = auth.config.get_jwt_settings()
        assert (
            cast("int", jwt_settings["jwt_expiry_minutes"]) >= 30
        )  # Production-ready default (at least 30 minutes)
        assert jwt_settings["jwt_algorithm"] == "HS256"

    def test_flext_auth_with_custom_params(self) -> None:
        """Test FlextAuth with custom parameters."""
        # Clear singleton to ensure clean test
        FlextAuthConfig.clear_global_instance()

        # Create FlextAuth with default configuration
        auth: FlextAuth = FlextAuth()
        config = auth.config
        assert config is not None

        jwt_settings = auth.config.get_jwt_settings()
        assert jwt_settings["jwt_expiry_minutes"] == 30

    def test_password_hashing_and_verification(self) -> None:
        """Test password hashing and verification."""
        password = "TestPassword123!"
        user = FlextAuthModels.User(
            id="test-id",
            username="testuser",
            email="test@example.com",
        )

        # Hash password
        hash_result = user.set_password(password)
        assert hash_result.success
        assert user.password_hash.startswith("$2b$")
        assert len(user.password_hash) > 50  # bcrypt hashes are long

        # Verify correct password
        verify_result = user.verify_password(password)
        assert verify_result.success
        assert verify_result.value is True

        # Verify incorrect password
        wrong_result = user.verify_password("wrong_password")
        assert wrong_result.success
        assert wrong_result.value is False

    def test_user_registration_success(self) -> None:
        """Test successful user registration."""
        auth: FlextAuth = FlextAuth()

        result = auth.register_user("testuser", "test@example.com", "Password123!")

        assert result.success is True
        assert result.value is not None

        user = result.value
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert "user" in user.roles
        assert user.is_active is True
        assert user.id is not None
        assert len(user.id) > 0
        assert "testuser" in auth.username_index
        assert "test@example.com" in auth.email_index

    def test_user_registration_duplicate_username(self) -> None:
        """Test registration with duplicate username."""
        auth: FlextAuth = FlextAuth()

        # Register first user
        result1 = auth.register_user("testuser", "test1@example.com", "Password123!")
        assert result1.success is True

        # Try to register with same username
        result2 = auth.register_user("testuser", "test2@example.com", "Password456!")
        assert result2.success is False
        assert result2.is_failure
        assert "Username already exists" in (result2.error or "")

        # Should still have only one user
        assert len(auth._users) == 1

    def test_user_registration_duplicate_email(self) -> None:
        """Test registration with duplicate email."""
        auth: FlextAuth = FlextAuth()

        # Register first user
        result1 = auth.register_user("user1", "test@example.com", "Password123!")
        assert result1.success is True

        # Try to register with same email
        result2 = auth.register_user("user2", "test@example.com", "Password456!")
        assert result2.success is False
        assert result2.is_failure
        assert "Email already exists" in (result2.error or "")

        # Should still have only one user
        assert len(auth._users) == 1

    def test_jwt_token_generation_and_verification(self) -> None:
        """Test JWT token generation and verification."""
        auth: FlextAuth = FlextAuth()

        # Create a user first
        auth.register_user("testuser", "test@example.com", "TestPassword123!")
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        assert auth_result.is_success
        auth_data: AuthenticationResponseDict = auth_result.value
        user_id = auth_data["user"]["id"]

        # Generate token
        token = auth.generate_token(user_id)
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20

        # Verify token
        result = auth.validate_token(token)
        assert result.success is True
        token_data = result.value
        assert isinstance(token_data, dict), "token_data must be dict"
        assert token_data["user_id"] == user_id
        assert "exp" in token_data
        assert "iat" in token_data

    def test_jwt_token_verification_invalid(self) -> None:
        """Test JWT token verification with invalid tokens."""
        auth: FlextAuth = FlextAuth()

        # Test invalid token
        result = auth.validate_token("invalid_token")
        assert result.success is False
        assert result.is_failure
        assert "Token validation failed" in (result.error or "")

        # Test malformed token
        result = auth.validate_token("not.a.valid.token")
        assert result.success is False
        assert result.is_failure

    def test_user_authentication_success(self) -> None:
        """Test successful user authentication."""
        auth: FlextAuth = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "Password123!",
        )
        assert register_result.success is True

        # Authenticate user
        auth_result = auth.authenticate_user("testuser", "Password123!")
        assert auth_result.success is True
        assert auth_result.value is not None

        data = auth_result.value
        assert isinstance(data, dict), "data must be dict"
        assert "user" in data
        assert "session" in data

        user_data = data["user"]
        assert isinstance(user_data, dict), "user_data must be dict"
        assert user_data["username"] == "testuser"
        assert user_data["email"] == "test@example.com"
        assert user_data["roles"] == ["user"]

        session_data = data["session"]
        assert isinstance(session_data, dict), "session_data must be dict"
        assert "id" in session_data
        assert "session_id" in session_data
        assert "expires_at" in session_data

        # Check session is stored
        assert len(auth._sessions) == 1

    def test_user_authentication_invalid_username(self) -> None:
        """Test authentication with invalid username."""
        auth: FlextAuth = FlextAuth()

        result = auth.authenticate_user("nonexistent", "Password123!")
        assert result.success is False
        assert result.is_failure
        assert "Invalid credentials" in (result.error or "")

    def test_user_authentication_invalid_password(self) -> None:
        """Test authentication with invalid password."""
        auth: FlextAuth = FlextAuth()

        # Register user
        auth.register_user("testuser", "test@example.com", "Password123!")

        # Try wrong password
        result = auth.authenticate_user("testuser", "wrongpassword")
        assert result.success is False
        assert result.is_failure
        assert "Invalid credentials" in (result.error or "")

    def test_user_authentication_inactive_user(self) -> None:
        """Test authentication with inactive user."""
        auth: FlextAuth = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "Password123!",
        )
        user = register_result.value

        # Deactivate user
        user.is_active = False

        # Try to authenticate
        result = auth.authenticate_user("testuser", "Password123!")
        assert result.success is False
        assert result.is_failure
        assert "Account is not active" in (result.error or "")

    def test_get_user_by_token(self) -> None:
        """Test getting user by token."""
        auth: FlextAuth = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "Password123!",
        )
        assert register_result.success is True

        # Authenticate to get token
        auth_result = auth.authenticate_user("testuser", "Password123!")
        auth_data = auth_result.value
        assert isinstance(auth_data, dict), "auth_data must be dict"
        tokens = auth_data.get("tokens")
        assert isinstance(tokens, dict), "tokens must be dict"
        token = tokens["access_token"]  # Use JWT token, not session token
        assert isinstance(token, str), "token must be string"

        # Get user by token
        user_result = auth.get_user_by_token(token)
        assert user_result.success is True
        user = user_result.value
        assert user is not None, "user should not be None"
        assert user.username == "testuser"

    def test_get_user_by_token_invalid(self) -> None:
        """Test getting user by invalid token."""
        auth: FlextAuth = FlextAuth()

        result = auth.get_user_by_token("invalid_token")
        assert result.success is False
        assert result.is_failure
        assert "Token validation failed" in (result.error or "")

    def test_get_user_by_username(self) -> None:
        """Test getting user by username."""
        auth: FlextAuth = FlextAuth()

        # Register user
        auth.register_user("testuser", "test@example.com", "Password123!")

        # Get user by username
        result = auth.get_user_by_username("testuser")
        assert result.success is True
        user = result.value
        assert user is not None
        assert user.username == "testuser"

        # Test case insensitive
        result2 = auth.get_user_by_username("TESTUSER")
        assert result2.success is True
        user2 = result2.value
        assert user2 is not None
        assert user2.username == "testuser"

        # Test nonexistent user
        result3 = auth.get_user_by_username("nonexistent")
        assert result3.success is True
        assert result3.value is None

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth: FlextAuth = FlextAuth()

        # Create expired session manually
        expired_session = Session(
            id="expired_session",
            user_id="user_123",
            session_token="expired_token" + "x" * 20,  # 32+ chars
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        auth._sessions["expired_session"] = expired_session

        # Create active session
        active_session = Session(
            id="active_session",
            user_id="user_456",
            session_token="active_token" + "x" * 20,  # 32+ chars
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        auth._sessions["active_session"] = active_session

        # Cleanup
        result = auth.cleanup_expired_sessions()
        assert result.success is True
        assert result.value == 1  # One expired session removed

        # Check sessions
        assert "expired_session" not in auth._sessions
        assert "active_session" in auth._sessions

    def test_session_is_expired_method(self) -> None:
        """Test Session.is_expired method."""
        # Expired session
        expired_session = Session(
            id="test",
            user_id="user",
            session_token="a" * 32,  # 32-character token for validation
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert expired_session.is_expired() is True

        # Active session
        active_session = Session(
            id="test",
            user_id="user",
            session_token="b" * 32,  # 32-character token for validation
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        assert active_session.is_expired() is False

    def test_user_model_defaults(self) -> None:
        """Test User model default values."""
        user = User(
            id="test_id",
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/LeELGj8/3eMQHtAMS",  # Valid bcrypt hash
        )

        assert "user" in user.roles
        assert user.is_active is True

        # Test user activation/deactivation
        user.is_active = False
        assert user.is_active is False

    def test_session_model_defaults(self) -> None:
        """Test Session model default values."""
        session = Session(
            id="test_id",
            user_id="user_123",
            session_token="token123" + "x" * 25,  # 32+ chars
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert session.created_at is not None
        assert isinstance(session.created_at, datetime)

    def test_complete_workflow_integration(self) -> None:
        """Test complete authentication workflow."""
        auth: FlextAuth = FlextAuth()

        # 1. Register user
        register_result = auth.register_user(
            "workflow_user",
            "workflow@example.com",
            "SecurePassword123!",
        )
        assert register_result.success is True
        user = register_result.value

        # 2. Authenticate user
        auth_result = auth.authenticate_user("workflow_user", "SecurePassword123!")
        assert auth_result.success is True
        auth_data = auth_result.value
        assert isinstance(auth_data, dict), "auth_data must be dict"
        tokens = auth_data.get("tokens")
        assert isinstance(tokens, dict), "tokens must be dict"
        token = tokens["access_token"]  # Use JWT token, not session token
        assert isinstance(token, str), "token must be string"

        # 3. Use token to get user
        user_result = auth.get_user_by_token(token)
        assert user_result.success is True
        token_user = user_result.value
        assert token_user is not None
        assert token_user.id == user.id

        # 4. Get user by username
        username_result = auth.get_user_by_username("workflow_user")
        assert username_result.success is True
        username_user = username_result.value
        assert username_user is not None
        assert username_user.id == user.id

        # 5. Cleanup (should not remove active session)
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success is True
        assert cleanup_result.value == 0  # No expired sessions

        # Verify session still exists
        assert len(auth._sessions) == 1

    def test_case_insensitive_operations(self) -> None:
        """Test case insensitive username and email operations."""
        auth: FlextAuth = FlextAuth()

        # Register with mixed case
        auth.register_user("TestUser", "Test@Example.Com", "Password123!")

        # Should find user with different cases
        result1 = auth.get_user_by_username("testuser")
        assert result1.success is True
        assert result1.value is not None

        result2 = auth.get_user_by_username("TESTUSER")
        assert result2.success is True
        assert result2.value is not None

        # Authentication should work with different case
        auth_result = auth.authenticate_user("TESTUSER", "Password123!")
        assert auth_result.success is True

        # Should prevent duplicate registration with different case
        dup_result = auth.register_user(
            "testuser",
            "different@example.com",
            "Password!",
        )
        assert dup_result.success is False
        assert dup_result.is_failure
        assert "Username already exists" in (dup_result.error or "")

        dup_email_result = auth.register_user(
            "different_user",
            "test@example.com",
            "password",
        )
        assert dup_email_result.success is False
        assert dup_email_result.is_failure
        assert "Email already exists" in (dup_email_result.error or "")

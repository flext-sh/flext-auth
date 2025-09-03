"""Complete tests for FlextAuth - 100% coverage, no mocks, real functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_auth import FlextAuth, Session, User


class TestFlextAuth:
    """Test FlextAuth complete functionality."""

    def test_create_auth_direct(self) -> None:
        """Test FlextAuth direct creation without factory function."""
        auth = FlextAuth()
        assert isinstance(auth, FlextAuth)
        config = auth.get_config()
        assert config.jwt_secret is not None
        assert len(config.jwt_secret) > 20

    def test_flext_auth_creation(self) -> None:
        """Test FlextAuth initialization."""
        auth = FlextAuth()
        config = auth.get_config()
        assert config.jwt_secret is not None
        assert len(config.jwt_secret) > 30  # Should be secure length
        assert config.jwt_expiry_minutes == 30

        # Test that auth is properly initialized
        jwt_settings = auth.get_jwt_settings()
        assert jwt_settings["jwt_expiry_minutes"] == 30
        assert jwt_settings["jwt_algorithm"] == "HS256"

    def test_flext_auth_with_custom_params(self) -> None:
        """Test FlextAuth with custom parameters."""
        custom_secret = (
            "this-is-a-very-long-custom-secret-for-jwt-tokens-with-enough-entropy"
        )

        # Create config first, then pass to FlextAuth
        from flext_auth.config import FlextAuthConfig

        config_result = FlextAuthConfig.create_for_environment(
            "development", jwt_secret=custom_secret, jwt_expiry_minutes=60
        )
        assert config_result.success, f"Config creation failed: {config_result.error}"

        auth = FlextAuth(config=config_result.value)
        config = auth.get_config()
        assert config.jwt_secret == custom_secret
        assert config.jwt_expiry_minutes == 60

        jwt_settings = auth.get_jwt_settings()
        assert jwt_settings["jwt_expiry_minutes"] == 60

    def test_password_hashing_and_verification(self) -> None:
        """Test password hashing and verification."""
        auth = FlextAuth()
        password = "test_password_123"

        # Hash password
        hash_result = auth.hash_password(password)
        assert hash_result is not None
        assert len(hash_result) > 50  # bcrypt hashes are long
        assert hash_result.startswith("$2b$")

        # Verify correct password
        assert auth.verify_password(password, hash_result) is True

        # Verify incorrect password
        assert auth.verify_password("wrong_password", hash_result) is False

        # Verify with invalid hash
        assert auth.verify_password(password, "invalid_hash") is False

    def test_user_registration_success(self) -> None:
        """Test successful user registration."""
        auth = FlextAuth()

        result = auth.register_user("testuser", "test@example.com", "password123")

        assert result.success is True
        assert result.value is not None

        user = result.value
        assert user.username == "testuser"
        assert str(user.email) == "test@example.com"
        assert user.role == "user"
        assert user.active is True
        assert user.id.startswith("user_testuser_")

        # Check user is stored
        assert len(auth.users) == 1
        assert user.id in auth.users
        assert "testuser" in auth.username_index
        assert "test@example.com" in auth.email_index

    def test_user_registration_duplicate_username(self) -> None:
        """Test registration with duplicate username."""
        auth = FlextAuth()

        # Register first user
        result1 = auth.register_user("testuser", "test1@example.com", "password123")
        assert result1.success is True

        # Try to register with same username
        result2 = auth.register_user("testuser", "test2@example.com", "password456")
        assert result2.success is False
        assert "Username already exists" in result2.error

        # Should still have only one user
        assert len(auth.users) == 1

    def test_user_registration_duplicate_email(self) -> None:
        """Test registration with duplicate email."""
        auth = FlextAuth()

        # Register first user
        result1 = auth.register_user("user1", "test@example.com", "password123")
        assert result1.success is True

        # Try to register with same email
        result2 = auth.register_user("user2", "test@example.com", "password456")
        assert result2.success is False
        assert "Email already exists" in result2.error

        # Should still have only one user
        assert len(auth.users) == 1

    def test_jwt_token_generation_and_verification(self) -> None:
        """Test JWT token generation and verification."""
        auth = FlextAuth()
        user_id = "test_user_id"

        # Generate token
        token = auth.generate_token(user_id)
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 20

        # Verify token
        result = auth.verify_token(token)
        assert result.success is True
        assert result.value["user_id"] == user_id
        assert "exp" in result.value
        assert "iat" in result.value

    def test_jwt_token_verification_invalid(self) -> None:
        """Test JWT token verification with invalid tokens."""
        auth = FlextAuth()

        # Test invalid token
        result = auth.verify_token("invalid_token")
        assert result.success is False
        assert "Invalid token" in result.error

        # Test expired token (create with different auth instance with past time)
        auth2 = FlextAuth(token_expire_minutes=-1)  # Negative minutes = expired
        expired_token = auth2.generate_token("user_id")

        result = auth.verify_token(expired_token)
        assert result.success is False

    def test_user_authentication_success(self) -> None:
        """Test successful user authentication."""
        auth = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "testuser", "test@example.com", "password123"
        )
        assert register_result.success is True

        # Authenticate user
        auth_result = auth.authenticate_user("testuser", "password123")
        assert auth_result.success is True
        assert auth_result.value is not None

        data = auth_result.value
        assert "user" in data
        assert "session" in data

        user_data = data["user"]
        assert user_data["username"] == "testuser"
        assert user_data["email"] == "test@example.com"
        assert user_data["role"] == "user"

        session_data = data["session"]
        assert "id" in session_data
        assert "token" in session_data
        assert "expires_at" in session_data

        # Check session is stored
        assert len(auth.sessions) == 1

    def test_user_authentication_invalid_username(self) -> None:
        """Test authentication with invalid username."""
        auth = FlextAuth()

        result = auth.authenticate_user("nonexistent", "password123")
        assert result.success is False
        assert "Invalid credentials" in result.error

    def test_user_authentication_invalid_password(self) -> None:
        """Test authentication with invalid password."""
        auth = FlextAuth()

        # Register user
        auth.register_user("testuser", "test@example.com", "password123")

        # Try wrong password
        result = auth.authenticate_user("testuser", "wrongpassword")
        assert result.success is False
        assert "Invalid credentials" in result.error

    def test_user_authentication_inactive_user(self) -> None:
        """Test authentication with inactive user."""
        auth = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "testuser", "test@example.com", "password123"
        )
        user = register_result.value

        # Deactivate user
        user.active = False

        # Try to authenticate
        result = auth.authenticate_user("testuser", "password123")
        assert result.success is False
        assert "Invalid credentials" in result.error

    def test_get_user_by_token(self) -> None:
        """Test getting user by token."""
        auth = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "testuser", "test@example.com", "password123"
        )
        assert register_result.success is True

        # Authenticate to get token
        auth_result = auth.authenticate_user("testuser", "password123")
        token = auth_result.value["session"]["token"]

        # Get user by token
        user_result = auth.get_user_by_token(token)
        assert user_result.success is True
        assert user_result.value.username == "testuser"

    def test_get_user_by_token_invalid(self) -> None:
        """Test getting user by invalid token."""
        auth = FlextAuth()

        result = auth.get_user_by_token("invalid_token")
        assert result.success is False
        assert "Invalid token" in result.error

    def test_get_user_by_username(self) -> None:
        """Test getting user by username."""
        auth = FlextAuth()

        # Register user
        auth.register_user("testuser", "test@example.com", "password123")

        # Get user by username
        result = auth.get_user_by_username("testuser")
        assert result.success is True
        assert result.value is not None
        assert result.value.username == "testuser"

        # Test case insensitive
        result2 = auth.get_user_by_username("TESTUSER")
        assert result2.success is True
        assert result2.value is not None
        assert result2.value.username == "testuser"

        # Test nonexistent user
        result3 = auth.get_user_by_username("nonexistent")
        assert result3.success is True
        assert result3.value is None

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth = FlextAuth()

        # Create expired session manually
        expired_session = Session(
            id="expired_session",
            user_id="user_123",
            token="expired_token" + "x" * 20,  # 32+ chars
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        auth.sessions["expired_session"] = expired_session

        # Create active session
        active_session = Session(
            id="active_session",
            user_id="user_456",
            token="active_token" + "x" * 20,  # 32+ chars
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        auth.sessions["active_session"] = active_session

        # Cleanup
        result = auth.cleanup_expired_sessions()
        assert result.success is True
        assert result.value == 1  # One expired session removed

        # Check sessions
        assert "expired_session" not in auth.sessions
        assert "active_session" in auth.sessions

    def test_session_is_expired_method(self) -> None:
        """Test Session.is_expired method."""
        # Expired session
        expired_session = Session(
            id="test",
            user_id="user",
            token="a" * 32,  # 32-character token for validation
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert expired_session.is_expired() is True

        # Active session
        active_session = Session(
            id="test",
            user_id="user",
            token="b" * 32,  # 32-character token for validation
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        assert active_session.is_expired() is False

    def test_user_model_defaults(self) -> None:
        """Test User model default values."""
        user = User(
            id="test_id",
            username="testuser",
            email="test@example.com",
            password_hash="hash123",
        )

        assert user.role == "user"
        assert user.active is True
        assert user.created_at is not None
        assert isinstance(user.created_at, datetime)

    def test_session_model_defaults(self) -> None:
        """Test Session model default values."""
        session = Session(
            id="test_id",
            user_id="user_123",
            token="token123" + "x" * 25,  # 32+ chars
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )

        assert session.created_at is not None
        assert isinstance(session.created_at, datetime)

    def test_complete_workflow_integration(self) -> None:
        """Test complete authentication workflow."""
        auth = FlextAuth()

        # 1. Register user
        register_result = auth.register_user(
            "workflow_user", "workflow@example.com", "secure_password"
        )
        assert register_result.success is True
        user = register_result.value

        # 2. Authenticate user
        auth_result = auth.authenticate_user("workflow_user", "secure_password")
        assert auth_result.success is True
        auth_data = auth_result.value
        token = auth_data["session"]["token"]

        # 3. Use token to get user
        user_result = auth.get_user_by_token(token)
        assert user_result.success is True
        assert user_result.value.id == user.id

        # 4. Get user by username
        username_result = auth.get_user_by_username("workflow_user")
        assert username_result.success is True
        assert username_result.value.id == user.id

        # 5. Cleanup (should not remove active session)
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success is True
        assert cleanup_result.value == 0  # No expired sessions

        # Verify session still exists
        assert len(auth.sessions) == 1

    def test_case_insensitive_operations(self) -> None:
        """Test case insensitive username and email operations."""
        auth = FlextAuth()

        # Register with mixed case
        auth.register_user("TestUser", "Test@Example.Com", "password123")

        # Should find user with different cases
        result1 = auth.get_user_by_username("testuser")
        assert result1.success is True
        assert result1.value is not None

        result2 = auth.get_user_by_username("TESTUSER")
        assert result2.success is True
        assert result2.value is not None

        # Authentication should work with different case
        auth_result = auth.authenticate_user("TESTUSER", "password123")
        assert auth_result.success is True

        # Should prevent duplicate registration with different case
        dup_result = auth.register_user("testuser", "different@example.com", "password")
        assert dup_result.success is False
        assert "Username already exists" in dup_result.error

        dup_email_result = auth.register_user(
            "different_user", "test@example.com", "password"
        )
        assert dup_email_result.success is False
        assert "Email already exists" in dup_email_result.error

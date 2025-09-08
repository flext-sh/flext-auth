"""Simplified real functionality tests for FlextAuth - without mocks, real functionality only.

Tests core authentication workflows using direct FlextAuth instances.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuth


class TestRealAuthenticationSimple:
    """Test FlextAuth real functionality without helper functions."""

    def test_basic_auth_workflow(self) -> None:
        """Test basic authentication workflow."""
        # Create auth instance directly
        auth: FlextAuth[object] = FlextAuth()

        # Register user
        register_result = auth.register_user(
            username="test_user", email="test@example.com", password="TestPassword123!"
        )
        assert register_result.success, f"Registration failed: {register_result.error}"
        user = register_result.value
        assert user.username == "test_user"

        # Authenticate user
        auth_result = auth.authenticate_user("test_user", "TestPassword123!")
        assert auth_result.success, f"Authentication failed: {auth_result.error}"
        auth_data = auth_result.value

        # Verify auth data structure
        assert "user" in auth_data
        assert "tokens" in auth_data
        assert "jwt_token" in auth_data

    def test_jwt_operations(self) -> None:
        """Test JWT token operations."""
        auth: FlextAuth[object] = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "jwt_user", "jwt@example.com", "JwtPassword123!"
        )
        assert register_result.success
        user = register_result.value

        # Generate JWT token
        token_result = auth.generate_jwt_token(user.id, expires_in_minutes=60)
        assert token_result.success
        jwt_token = token_result.value

        # Validate token
        validation_result = auth.validate_token(jwt_token)
        assert validation_result.success
        payload = validation_result.value
        assert payload["user_id"] == user.id

    def test_password_operations(self) -> None:
        """Test password hashing and verification."""
        auth: FlextAuth[object] = FlextAuth()

        # Test password hashing
        password = "SecurePassword123!"
        hashed = auth.hash_password(password)
        assert hashed.startswith("$2b$")

        # Test password verification
        assert auth.verify_password(password, hashed)
        assert not auth.verify_password("wrong_password", hashed)

    def test_user_lookup(self) -> None:
        """Test user lookup operations."""
        auth: FlextAuth[object] = FlextAuth()

        # Register user
        register_result = auth.register_user(
            "lookup_user", "lookup@example.com", "LookupPassword123!"
        )
        assert register_result.success
        user = register_result.value

        # Lookup by username
        user_result = auth.get_user_by_username("lookup_user")
        assert user_result.success
        found_user = user_result.value
        assert found_user is not None
        assert found_user.username == "lookup_user"

        # Lookup by ID
        user_by_id_result = auth.get_user_by_id(user.id)
        assert user_by_id_result.success
        found_by_id = user_by_id_result.value
        assert found_by_id is not None
        assert found_by_id.id == user.id

    def test_session_management(self) -> None:
        """Test session management."""
        auth: FlextAuth[object] = FlextAuth()

        # Register and authenticate user
        register_result = auth.register_user(
            "session_user", "session@example.com", "SessionPassword123!"
        )
        assert register_result.success
        user = register_result.value

        auth_result = auth.authenticate_user("session_user", "SessionPassword123!")
        assert auth_result.success

        # Get user sessions
        sessions_result = auth.get_user_sessions(user.id)
        assert sessions_result.success
        sessions = sessions_result.value
        assert len(sessions) >= 1

        # Test session cleanup
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success
        assert isinstance(cleanup_result.value, int)

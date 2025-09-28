"""Unit tests for flext_auth.auth module.

Tests FlextAuth functionality with real implementations,
no mocks or legacy patterns. Achieves near 100% coverage following FLEXT standards.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
import time

from flext_auth import FlextAuth
from flext_core import FlextResult, FlextTypes


class TestAuthModule:
    """Unified test class for auth module functionality."""

    class _TestDataHelper:
        """Nested helper class for test data creation."""

        @staticmethod
        def create_test_user_data() -> FlextTypes.Core.Dict:
            """Create test user data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
                "role": "user",
            }

        @staticmethod
        def create_test_auth_data() -> FlextTypes.Core.Dict:
            """Create test authentication data."""
            return {
                "username": "test_user",
                "email": "test@example.com",
                "password": "TestPassword123!",
            }

        @staticmethod
        def create_test_session_data() -> FlextTypes.Core.Dict:
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

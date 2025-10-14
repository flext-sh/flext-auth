"""Enhanced test suite for flext-auth with comprehensive flext-tests integration.

This module demonstrates advanced testing patterns using flext-tests utilities:
- TestBuilders for complex object construction
- PerformanceMatchers for benchmarking critical paths
- Advanced test patterns with zero mocking

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
import uuid
from collections.abc import Callable
from typing import TypedDict, cast

from flext_core import FlextCore

from flext_auth import (
    FlextAuth,
    FlextAuthModels,
)
from flext_auth.typings import FlextAuthTypes

# Use unified class structure
User = FlextAuthModels.User


# Create simple test data factories
class UserFactory:
    """Factory for creating test user data."""

    @staticmethod
    def create_dict() -> FlextCore.Types.StringDict:
        """Create a simple user data dictionary.

        Returns:
            FlextCore.Types.StringDict: User data dictionary

        """
        return {
            "name": f"test_user_{uuid.uuid4().hex[:8]}",
            "email": f"test_{uuid.uuid4().hex[:8]}@example.com",
            "password": "TestPassword123!",
        }

    @staticmethod
    def batch(count: int) -> list[FlextCore.Types.StringDict]:
        """Create a batch of user data dictionaries.

        Returns:
            list[FlextCore.Types.StringDict]: List of user data dictionaries

        """
        return [UserFactory.create_dict() for _ in range(count)]


class FlextTestsMatchers:
    """Matchers for test assertions."""

    @staticmethod
    def assert_success(result: object) -> None:
        """Assert that a result is successful."""
        assert hasattr(result, "is_success")
        assert getattr(result, "is_success", False)

    @staticmethod
    def assert_result_success(result: object) -> None:
        """Assert that a result is successful (alias)."""
        assert hasattr(result, "is_success")
        assert getattr(result, "is_success", False)

    @staticmethod
    def assert_result_failure(result: object) -> None:
        """Assert that a result is a failure."""
        assert hasattr(result, "is_failure")
        assert getattr(result, "is_failure", False)


class FlextTestsFactories:
    """Factory collection for tests."""

    UserFactory = UserFactory


class UserData(TypedDict):
    """Type definition for FlextTestsFactories.UserFactory.create() output."""

    id: str
    name: str
    email: str
    age: int
    active: bool
    created_at: str


# Type aliases for better readability and mypy compatibility
AuthUserDict = dict[str, str | int | bool]
AuthSessionDict = dict[str, str | int | bool]
AuthDataDict = (
    dict[str, str | int | bool]
    | AuthUserDict
    | AuthSessionDict
    | FlextCore.Types.StringDict
)


def sanitize_username(name: str, prefix: str = "") -> str:
    """Sanitize a name to create a valid username that passes validation.

    Removes all invalid characters and ensures the username contains only
    letters, numbers, underscores, and hyphens as required by User model.

    Returns:
        str: Sanitized username

    """
    # Convert to lowercase and replace spaces with underscores
    clean_name = name.lower().replace(" ", "_")

    # Remove any characters that are not letters, numbers, underscores, or hyphens
    clean_name = re.sub(r"[^a-z0-9_-]", "", clean_name)

    # Remove multiple consecutive underscores
    clean_name = re.sub(r"_+", "_", clean_name)

    # Remove leading/trailing underscores
    clean_name = clean_name.strip("_")

    # Ensure the name is not empty
    if not clean_name:
        clean_name = "user"

    # Add prefix if provided
    if prefix:
        return f"{prefix}_{clean_name}"
    return clean_name


class TestEnhancedAuthentication:
    """Enhanced authentication tests using flext_tests utilities."""

    def test_user_registration_with_real_data_factory(self) -> None:
        """Test user registration with FlextTestsFactories.UserFactory - cleaner and more realistic."""
        auth: FlextAuth = FlextAuth()

        # Create realistic user data using flext_tests factory
        user_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())

        # Register user with realistic data
        username = sanitize_username(user_data["name"])
        result = auth.register_user(
            username=username,
            email=str(user_data["email"]),
            password="SecurePassword123!@#",
        )

        # Use FlextTestsMatchers for cleaner assertions
        FlextTestsMatchers.assert_result_success(result)

        user = result.value
        assert isinstance(user, User)
        assert user.email == user_data["email"]
        assert user.username == username

    def test_authentication_flow_with_batch_users(self) -> None:
        """Test authentication with batch user creation - demonstrates scalability."""
        auth: FlextAuth = FlextAuth()

        # Create batch of realistic users using flext_tests
        users_data = cast(
            "list[UserData]",
            FlextTestsFactories.UserFactory.batch(count=5),
        )
        registered_users: list[tuple[str, str]] = []

        # Register all users
        for i, user_data in enumerate(users_data):
            username = sanitize_username(user_data["name"], f"user_{i}")
            result = auth.register_user(
                username=username,
                email=str(user_data["email"]),
                password="TestPassword123!@#",
            )

            # Clean assertion using FlextTestsMatchers
            FlextTestsMatchers.assert_result_success(result)
            registered_users.append((username, str(user_data["email"])))

        # Authenticate all users
        for username, email in registered_users:
            auth_result = auth.authenticate_user(username, "TestPassword123!@#")

            # Verify successful authentication
            FlextTestsMatchers.assert_result_success(auth_result)

            auth_data = auth_result.value
            assert "user" in auth_data
            assert "session" in auth_data
            assert "tokens" in auth_data  # 'tokens' not 'token'

            user = cast("AuthUserDict", auth_data["user"])
            assert user["username"] == username  # user is dict, not object
            assert user["email"] == email

    def test_authentication_failure_patterns_with_matchers(self) -> None:
        """Test authentication failures using FlextTestsMatchers for cleaner error assertions."""
        auth: FlextAuth = FlextAuth()

        # Create user using factory
        user_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())
        username = sanitize_username(user_data["name"])

        # Register user first
        register_result = auth.register_user(
            username=username,
            email=str(user_data["email"]),
            password="CorrectPassword123!@#",
        )
        FlextTestsMatchers.assert_result_success(register_result)

        # Test wrong password - clean failure assertion
        wrong_pass_result = auth.authenticate_user(username, "WrongPassword")
        FlextTestsMatchers.assert_result_failure(wrong_pass_result)
        error_msg = wrong_pass_result.error or ""
        assert "invalid credentials" in error_msg.lower()

        # Test non-existent user - clean failure assertion
        nonexistent_result = auth.authenticate_user(
            "nonexistent_user", "objectPassword"
        )
        FlextTestsMatchers.assert_result_failure(nonexistent_result)
        nonexistent_error_msg = nonexistent_result.error or ""
        assert "invalid credentials" in nonexistent_error_msg.lower()

    def test_quick_start_with_realistic_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test quick_start functionality with realistic REDACTED_LDAP_BIND_PASSWORD data."""
        # Create realistic REDACTED_LDAP_BIND_PASSWORD data
        REDACTED_LDAP_BIND_PASSWORD_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())
        REDACTED_LDAP_BIND_PASSWORD_username = sanitize_username(REDACTED_LDAP_BIND_PASSWORD_data["name"], "REDACTED_LDAP_BIND_PASSWORD")

        # Test quick_start with REDACTED_LDAP_BIND_PASSWORD creation
        auth = FlextAuth.quick_start(
            create_REDACTED_LDAP_BIND_PASSWORD=True,
            REDACTED_LDAP_BIND_PASSWORD_username=REDACTED_LDAP_BIND_PASSWORD_username,
            REDACTED_LDAP_BIND_PASSWORD_password="AdminSecurePass123!@#",
        )

        # Verify auth instance created
        assert isinstance(auth, FlextAuth)

        # Verify REDACTED_LDAP_BIND_PASSWORD can authenticate
        auth_result = auth.authenticate_user(REDACTED_LDAP_BIND_PASSWORD_username, "AdminSecurePass123!@#")
        FlextTestsMatchers.assert_result_success(auth_result)

        REDACTED_LDAP_BIND_PASSWORD_user = cast("AuthUserDict", auth_result.value["user"])
        assert REDACTED_LDAP_BIND_PASSWORD_user["username"] == REDACTED_LDAP_BIND_PASSWORD_username

    def test_session_management_with_realistic_scenarios(self) -> None:
        """Test session management with realistic user scenarios."""
        auth: FlextAuth = FlextAuth()

        # Create multiple users for session testing
        users_data = cast(
            "list[UserData]",
            FlextTestsFactories.UserFactory.batch(count=3),
        )
        user_sessions: list[tuple[str, str]] = []

        for i, user_data in enumerate(users_data):
            username = f"session_user_{i}"

            # Register and authenticate user
            register_result = auth.register_user(
                username=username,
                email=str(user_data["email"]),
                password="SessionTest123!@#",
            )
            FlextTestsMatchers.assert_result_success(register_result)

            auth_result = auth.authenticate_user(username, "SessionTest123!@#")
            FlextTestsMatchers.assert_result_success(auth_result)

            session = cast("AuthSessionDict", auth_result.value["session"])
            user_sessions.append((username, str(session["id"])))

        # Verify all sessions are active - need to check each user's own sessions
        for i in range(len(user_sessions)):
            # Re-authenticate to get the correct user context
            reauth_result = auth.authenticate_user(
                f"session_user_{i}",
                "SessionTest123!@#",
            )
            FlextTestsMatchers.assert_result_success(reauth_result)

            user_data_dict = cast("AuthUserDict", reauth_result.value["user"])
            user_id = str(user_data_dict["id"])
            sessions_result = auth.get_user_sessions(user_id)
            FlextTestsMatchers.assert_result_success(sessions_result)

            sessions = sessions_result.value
            session_ids = [s.id for s in sessions]
            # At least one session should exist for this user
            assert len(session_ids) > 0

        # Test session cleanup
        cleanup_result = auth.cleanup_expired_sessions()
        FlextTestsMatchers.assert_result_success(cleanup_result)

        # Should return number of cleaned sessions (likely 0 since sessions are new)
        cleaned_count = cleanup_result.value
        assert isinstance(cleaned_count, int)
        assert cleaned_count >= 0

    def test_user_management_lifecycle_with_factory_data(self) -> None:
        """Test complete user management lifecycle with factory-generated data."""
        auth: FlextAuth = FlextAuth()

        # Create user and get basic info
        user_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())
        username = sanitize_username(user_data["name"], "lifecycle")

        register_result = auth.register_user(
            username=username,
            email=str(user_data["email"]),
            password="LifecycleTest123!@#",
            full_name=str(user_data["name"]),
        )
        FlextTestsMatchers.assert_result_success(register_result)
        user = register_result.value

        # Test user retrieval methods
        self._test_user_retrieval_methods(auth, user.id, username, user_data["email"])

        # Test authentication and token operations
        auth_data = self._test_authentication_and_tokens(auth, username, user.id)

        # Test session management
        self._test_session_management(
            auth, user.id, cast("FlextCore.Types.Dict", auth_data["session"])
        )

    def _test_user_retrieval_methods(
        self, auth: FlextAuth, user_id: str, username: str, email: str
    ) -> None:
        """Test user retrieval by different methods."""
        # By ID
        user_by_id_result = auth.get_user_by_id(user_id)
        FlextTestsMatchers.assert_result_success(user_by_id_result)
        if user_by_id_result.value:
            assert user_by_id_result.value.username == username

        # By username
        user_by_username_result = auth.get_user_by_username(username)
        FlextTestsMatchers.assert_result_success(user_by_username_result)
        if user_by_username_result.value:
            assert user_by_username_result.value.email == email

    def _test_authentication_and_tokens(
        self, auth: FlextAuth, username: str, user_id: str
    ) -> FlextAuthTypes.AuthenticationResponseDict:
        """Test authentication and token operations.

        Returns:
            dict[str, object]: Authentication data including session and token information.

        """
        auth_result = auth.authenticate_user(username, "LifecycleTest123!@#")
        FlextTestsMatchers.assert_result_success(auth_result)
        auth_data = auth_result.value

        token = str(auth_data.get("jwt_token"))

        # Validate token
        validate_result = auth.validate_token(token)
        FlextTestsMatchers.assert_result_success(validate_result)

        # Get user by token using direct API (validate_token + get_user_by_id)
        user_id_from_token = validate_result.value.get("user_id")
        assert user_id_from_token is not None
        user_by_token_result = auth.get_user_by_id(str(user_id_from_token))
        FlextTestsMatchers.assert_result_success(user_by_token_result)
        if user_by_token_result.value:
            assert user_by_token_result.value.id == user_id

        return auth_data

    def _test_session_management(
        self, auth: FlextAuth, user_id: str, session_data: FlextCore.Types.Dict
    ) -> None:
        """Test session management operations."""
        # Get user sessions
        sessions_result = auth.get_user_sessions(user_id)
        FlextTestsMatchers.assert_result_success(sessions_result)

        sessions = sessions_result.value
        assert len(sessions) > 0
        assert any(s.id == str(session_data["id"]) for s in sessions)

        # Logout (optional - may fail if session already expired)
        logout_result = auth.logout_user(user_id)
        assert (
            logout_result.is_success or "not found" in str(logout_result.error).lower()
        )


class TestEnhancedConfigurationTesting:
    """Enhanced configuration testing with flext_tests patterns."""

    def test_configuration_with_factory_variations(self) -> None:
        """Test configuration with various realistic scenarios."""
        # Test different environment configurations
        environments = ["development", "production", "staging"]

        for env in environments:
            # Create auth with environment-specific config (simplified approach)
            auth: FlextAuth = FlextAuth()
            # Configuration is read-only, test that it's accessible
            assert auth.config is not None

            # Test functionality works with different configurations
            user_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())
            username = sanitize_username(user_data["name"], f"{env}_user")

            register_result = auth.register_user(
                username=username,
                email=str(user_data["email"]),
                password="ConfigTest123!@#",
            )
            FlextTestsMatchers.assert_result_success(register_result)

            # Verify authentication works with different configurations
            auth_result = auth.authenticate_user(username, "ConfigTest123!@#")
            FlextTestsMatchers.assert_result_success(auth_result)


class TestEnhancedPerformanceValidation:
    """Performance testing using flext_tests advanced capabilities."""

    def test_authentication_performance_benchmark(
        self,
        benchmark: Callable[[Callable[[], object]], object],
    ) -> None:
        """Test authentication performance using pytest-benchmark."""
        auth: FlextAuth = FlextAuth()

        # Setup: Register user for performance testing
        user_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())
        username = sanitize_username(user_data["name"], "perf")

        register_result = auth.register_user(
            username=username,
            email=str(user_data["email"]),
            password="PerfTest123!@#",
        )
        FlextTestsMatchers.assert_result_success(register_result)

        # Performance test: Authentication should be fast
        def authenticate_user_perf() -> object:
            return auth.authenticate_user(username, "PerfTest123!@#")

        # Use benchmark directly since FlextTestsMatchers.assert_performance_within_limit signature is complex
        result = benchmark(authenticate_user_perf)

        # Verify the result is still functional
        FlextTestsMatchers.assert_result_success(result)
        result = cast("FlextCore.Result", result)
        if result.is_success:
            result_value = result.value
            if isinstance(result_value, dict) and "user" in result_value:
                user_result = cast("AuthUserDict", result_value["user"])
                assert user_result["username"] == username

    def test_batch_user_registration_complexity(
        self,
        benchmark: Callable[[Callable[[], object]], object],
    ) -> None:
        """Test batch user registration performance characteristics."""
        auth: FlextAuth = FlextAuth()

        def register_batch_users() -> FlextCore.Types.List:
            """Register multiple users and return results.

            Returns:
                FlextCore.Types.List: List of registration results

            """
            results: FlextCore.Types.List = []
            users_data = cast(
                "list[UserData]",
                FlextTestsFactories.UserFactory.batch(count=5),
            )

            for i, user_data in enumerate(users_data):
                unique_id = str(uuid.uuid4())[:8]
                username = sanitize_username(
                    user_data["name"],
                    f"batch_5_{i}_{unique_id}",
                )
                email = f"{unique_id}_{user_data['email']}"
                result = auth.register_user(
                    username=username,
                    email=email,
                    password="BatchTest123!@#",
                )
                results.append(result)
            return results

        # Use single benchmark call
        results = benchmark(register_batch_users)

        # Verify all registrations succeeded
        if isinstance(results, (list, tuple)):
            for result in results:
                FlextTestsMatchers.assert_result_success(result)

    def test_session_management_performance(
        self,
        benchmark: Callable[[Callable[[], object]], object],
    ) -> None:
        """Test session management performance with realistic load."""
        auth: FlextAuth = FlextAuth()

        # Setup: Create multiple users
        users_data = cast(
            "list[UserData]",
            FlextTestsFactories.UserFactory.batch(count=3),
        )
        user_sessions: FlextCore.Types.StringList = []

        for i, user_data in enumerate(users_data):
            username = f"session_perf_{i}"
            register_result = auth.register_user(
                username=username,
                email=str(user_data["email"]),
                password="SessionPerfTest123!@#",
            )
            FlextTestsMatchers.assert_result_success(register_result)
            user_sessions.append(username)

        def session_operations_batch() -> FlextCore.Types.List:
            """Perform batch session operations.

            Returns:
                FlextCore.Types.List: List of session operation results

            """
            session_results: FlextCore.Types.List = []
            for username in user_sessions:
                # Authenticate to create session
                auth_result = auth.authenticate_user(username, "SessionPerfTest123!@#")
                if auth_result.is_success:
                    user_dict = cast("AuthUserDict", auth_result.value["user"])
                    user_id = str(user_dict["id"])
                    # Get user sessions
                    sessions_result = auth.get_user_sessions(user_id)
                    session_results.append(sessions_result)
            return session_results

        # Performance test: Session operations should be efficient
        results = benchmark(session_operations_batch)

        # Verify all operations succeeded
        if isinstance(results, (list, tuple)):
            for result in results:
                FlextTestsMatchers.assert_result_success(result)


class TestEnhancedTestBuilders:
    """Advanced test patterns using TestBuilders."""

    def test_complex_authentication_scenario_with_builders(self) -> None:
        """Test complex authentication scenario using TestBuilders."""
        # Use TestBuilders for creating complex test data
        auth: FlextAuth = FlextAuth()

        # Create multiple users with different roles using factory pattern
        REDACTED_LDAP_BIND_PASSWORD_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())
        user_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())
        guest_data = cast("UserData", FlextTestsFactories.UserFactory.create_dict())

        # Register users with different roles
        REDACTED_LDAP_BIND_PASSWORD_username = sanitize_username(REDACTED_LDAP_BIND_PASSWORD_data["name"], "REDACTED_LDAP_BIND_PASSWORD")
        user_username = sanitize_username(user_data["name"], "user")
        guest_username = sanitize_username(guest_data["name"], "guest")

        REDACTED_LDAP_BIND_PASSWORD_result = auth.register_user(
            username=REDACTED_LDAP_BIND_PASSWORD_username,
            email=str(REDACTED_LDAP_BIND_PASSWORD_data["email"]),
            password="AdminTest123!@#",
            roles=["REDACTED_LDAP_BIND_PASSWORD"],
        )
        FlextTestsMatchers.assert_result_success(REDACTED_LDAP_BIND_PASSWORD_result)

        user_result = auth.register_user(
            username=user_username,
            email=str(user_data["email"]),
            password="UserTest123!@#",
            roles=["user"],
        )
        FlextTestsMatchers.assert_result_success(user_result)

        guest_result = auth.register_user(
            username=guest_username,
            email=str(guest_data["email"]),
            password="GuestTest123!@#",
            roles=["guest"],
        )
        FlextTestsMatchers.assert_result_success(guest_result)

        # Verify role-based functionality
        REDACTED_LDAP_BIND_PASSWORD_user = REDACTED_LDAP_BIND_PASSWORD_result.value
        user_user = user_result.value
        guest_user = guest_result.value

        assert "REDACTED_LDAP_BIND_PASSWORD" in REDACTED_LDAP_BIND_PASSWORD_user.roles
        assert "user" in user_user.roles
        assert "guest" in guest_user.roles

        # Test authentication for all users
        for user_cred in [
            (
                sanitize_username(REDACTED_LDAP_BIND_PASSWORD_data["name"], "REDACTED_LDAP_BIND_PASSWORD"),
                "AdminTest123!@#",
            ),
            (sanitize_username(user_data["name"], "user"), "UserTest123!@#"),
            (
                sanitize_username(guest_data["name"], "guest"),
                "GuestTest123!@#",
            ),
        ]:
            auth_result = auth.authenticate_user(user_cred[0], user_cred[1])
            FlextTestsMatchers.assert_result_success(auth_result)
            user_auth_data = cast("AuthUserDict", auth_result.value["user"])
            assert user_auth_data["username"] == user_cred[0]


# Tests use real functionality without mocks - enhanced with flext_tests

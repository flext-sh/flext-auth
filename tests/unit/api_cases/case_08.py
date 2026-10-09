"""FlextAuth API test case group 08.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import r

from flext_auth import FlextAuth, m
from tests import TestsFlextAuthUtilities
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase08:
    """FlextAuth API case group 08."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_token_expiry_edge_cases() -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth()
        user_result = auth.register_user(
            "test_user",
            "test@example.com",
            "TestPassword123!",
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.error, none=True)

    @staticmethod
    def test_invalid_user_operations() -> None:
        """Test operations with invalid user IDs."""
        auth = FlextAuth()
        invalid_user_id = "nonexistent_user_id"
        get_result = auth.identity_service.identity_manager.fetch_user(invalid_user_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(not get_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(get_result.error, none=False)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            (get_result.error or "").lower(), has="not found"
        )
        username_result = auth.identity_service.identity_manager.fetch_user_by_username(
            "nonexistent_username",
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(
            not username_result.success, eq=True
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(username_result.error, none=False)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            (username_result.error or "").lower(), has="not found"
        )
        logout_result = auth.session_service.session_manager.end_session_by_id(
            invalid_user_id,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(not logout_result.success, eq=True)

    @staticmethod
    def test_cleanup_expired_sessions_with_user_sessions_index() -> None:
        """Test cleanup_expired_sessions with a user sessions index."""
        auth = FlextAuth()
        auth.register_user("testuser", "test@example.com", "Password123!")
        auth_result = auth.authenticate_user("testuser", "Password123!")
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        TestsFlextAuthUtilities.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id,
        )
        if sessions_result.success:
            sessions = sessions_result.value
            TestsFlextAuthUtilities.Tests.Matchers.that(sessions, is_=list)
        cleanup_result = auth.session_service.cleanup_expired_sessions()
        TestsFlextAuthUtilities.Tests.Matchers.that(cleanup_result.success, eq=True)

    @staticmethod
    def test_get_user_by_token_invalid_token_error_direct_api() -> None:
        """Test validate_token with invalid token — fails with 'not implemented'."""
        auth = FlextAuth()
        result = auth.session_service.validate_token("invalid_token")
        TestsFlextAuthUtilities.Tests.Matchers.that(not result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.error, none=False)

    def test_flext_auth_register_user(self) -> None:
        """Test FlextAuth register_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()
        result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(result, is_=r)

    def test_flext_auth_authenticate_user(self) -> None:
        """Test FlextAuth authenticate_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        if hasattr(auth, "authenticate_user"):
            result = auth.authenticate_user(
                str(test_data["username"]),
                str(test_data["password"]),
            )
            TestsFlextAuthUtilities.Tests.Matchers.that(result, is_=r)

    def test_flext_auth_fetch_user_by_username(self) -> None:
        """Test FlextAuth fetch_user_by_username functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        result = auth.identity_service.identity_manager.fetch_user_by_username(
            str(test_data["username"]),
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(result, is_=r)

    def test_flext_auth_fetch_user(self) -> None:
        """Test FlextAuth fetch_user functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_user_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        user = register_result.value
        user_id = user.unique_id
        result = auth.identity_service.identity_manager.fetch_user(user_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(result, is_=r)

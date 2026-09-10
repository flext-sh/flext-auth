"""Shared FlextAuth API test helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth import FlextAuth
from tests import m, u

if TYPE_CHECKING:
    from tests import t


class FlextAuthApiTestDataHelper:
    """Nested helper class for test data creation."""

    @staticmethod
    def registered_session() -> tuple[FlextAuth, m.Auth.AuthIdentity, t.JsonMapping]:
        """Register and authenticate one identity through the public facade."""
        auth = FlextAuth()
        test_data = FlextAuthApiTestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]), str(test_data["password"])
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        return auth, identity, test_data

    @staticmethod
    def create_test_user_data() -> t.JsonMapping:
        """Create test user data."""
        return {
            "username": "test_user",
            "email": "test@example.com",
            "password": "TestPassword123!",
            "role": "user",
        }

    @staticmethod
    def create_test_auth_data() -> t.JsonMapping:
        """Create test authentication data."""
        return {
            "username": "test_user",
            "email": "test@example.com",
            "password": "TestPassword123!",
        }

    @staticmethod
    def create_test_session_data() -> t.JsonMapping:
        """Create test session data."""
        return {
            "user_id": "user_123",
            "session_id": "session_123",
            "expires_at": "2025-12-31T23:59:59Z",
        }


__all__: list[str] = ["FlextAuthApiTestDataHelper"]

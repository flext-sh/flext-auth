"""Shared FlextAuth API test helpers."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from tests.typings import t


class FlextAuthApiTestDataHelper:
    """Nested helper class for test data creation."""

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

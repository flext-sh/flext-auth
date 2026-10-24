"""Shared FlextAuth API test helpers.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Final

from flext_auth import FlextAuth
from tests import TestsFlextAuthUtilities, c

if TYPE_CHECKING:
    from flext_auth import p, t


class TestsFlextAuthApiTestDataHelper:
    """Nested helper class for test data creation."""

    UNIT_TEST_CREDENTIAL_TOKEN: Final[str] = "flext-auth-unit-" + "9f2k"

    @staticmethod
    def registered_session() -> tuple[FlextAuth, p.Auth.Identity, t.StrMapping]:
        """Register and authenticate one identity through the public facade.

        Returns:
            The facade, its public identity result, and the submitted string fields.

        """
        auth = FlextAuth()
        test_data = TestsFlextAuthApiTestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=test_data["username"],
            email=test_data["email"],
            password=test_data["password"],
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            test_data["username"],
            test_data["password"],
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        return auth, identity, test_data

    @staticmethod
    def create_test_user_data() -> t.StrMapping:
        """Create test user data.

        Returns:
            The string fields consumed by user registration.

        """
        return {
            "username": "test_user",
            "email": "test@example.com",
            "password": TestsFlextAuthApiTestDataHelper.UNIT_TEST_CREDENTIAL_TOKEN,
            "role": c.ContextScope.USER,
        }

    @staticmethod
    def create_test_auth_data() -> t.StrMapping:
        """Create test authentication data.

        Returns:
            The string fields consumed by authentication.

        """
        return {
            "username": "test_user",
            "email": "test@example.com",
            "password": TestsFlextAuthApiTestDataHelper.UNIT_TEST_CREDENTIAL_TOKEN,
        }

    @staticmethod
    def create_test_session_data() -> t.JsonMapping:
        """Create test session data.

        Returns:
            The resulting ``t.JsonMapping``.

        """
        return {
            c.ContextKey.USER_ID: "user_123",
            "session_id": "session_123",
            "expires_at": "2025-12-31T23:59:59Z",
        }

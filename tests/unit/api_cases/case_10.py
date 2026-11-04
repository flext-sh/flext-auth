"""FlextAuth API test case group 10.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time

from flext_auth import FlextAuth
from tests import c, m, r, tm
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase10:
    """FlextAuth API case group 10."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_flext_auth_error_handling() -> None:
        """Test auth module error handling patterns."""
        auth = FlextAuth()
        result = auth.register_user(username="", email="invalid_email", password="")
        tm.that(result, is_=r)
        tm.that(not result.success, eq=True)
        result = auth.authenticate_user("invalid_user", "invalid_password")
        tm.that(result, is_=r)
        tm.that(not result.success, eq=True)
        result = auth.identity_service.identity_manager.fetch_user_by_username(
            "non_existent_user",
        )
        tm.that(result, is_=r)
        tm.that(not result.success, eq=True)
        tm.that(result.error, none=False)
        tm.that((result.error or "").lower(), has="not found")

    @staticmethod
    def test_flext_auth_with_flext_tests() -> None:
        """Test auth functionality with flext_tests infrastructure."""
        auth = FlextAuth()
        credential = TestsFlextAuthApiTestDataHelper.UNIT_TEST_CREDENTIAL_TOKEN
        test_user_data = {
            "username": "flext_test_user",
            "email": "flext_test@example.com",
            "password": credential,
        }
        test_auth_data = {
            "username": "flext_test_user",
            "password": credential,
        }
        result = auth.register_user(
            username=test_user_data["username"],
            email=test_user_data["email"],
            password=test_user_data["password"],
        )
        tm.that(result, is_=r)
        tm.that(result.success, eq=True)
        result = auth.authenticate_user(
            test_auth_data["username"],
            test_auth_data["password"],
        )
        tm.that(result, is_=r)
        tm.that(result.success, eq=True)

    @staticmethod
    def test_flext_auth_docstring() -> None:
        """Test that FlextAuth has proper docstring."""
        tm.that(FlextAuth.__doc__, none=False)
        tm.that(len((FlextAuth.__doc__ or "").strip()) > 0, eq=True)

    @staticmethod
    def test_flext_auth_with_real_data() -> None:
        """Test auth functionality with realistic data scenarios."""
        auth = FlextAuth()
        credential = TestsFlextAuthApiTestDataHelper.UNIT_TEST_CREDENTIAL_TOKEN
        realistic_users = [
            {
                "username": "admin_user",
                "email": "admin@company.com",
                "password": f"{credential}-admin",
                "role": "admin",
            },
            {
                "username": "regular_user",
                "email": "user@company.com",
                "password": f"{credential}-regular",
                "role": c.ContextScope.USER,
            },
            {
                "username": "guest_user",
                "email": "guest@company.com",
                "password": f"{credential}-guest",
                "role": "guest",
            },
        ]
        for user_data in realistic_users:
            result = auth.register_user(
                username=user_data["username"],
                email=user_data["email"],
                password=user_data["password"],
                roles=[user_data["role"]] if "role" in user_data else None,
            )
            tm.that(result, is_=r)
            tm.that(result.success, eq=True)
        for user_data in realistic_users:
            result = auth.authenticate_user(
                user_data["username"],
                user_data["password"],
            )
            tm.that(result, is_=r)
            tm.that(result.success, eq=True)

    def test_flext_auth_integration_patterns(self) -> None:
        """Test auth integration patterns — token ops succeed as expected."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=test_user_data["username"],
            email=test_user_data["email"],
            password=test_user_data["password"],
        )
        tm.that(register_result, is_=r, ok=True)
        auth_result = auth.authenticate_user(
            test_auth_data["username"],
            test_auth_data["password"],
        )
        tm.that(auth_result, is_=r, ok=True)
        authenticated_identity = auth_result.value
        tm.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=authenticated_identity.unique_id)
        tm.that(token_result, is_=r, ok=True)

    def test_flext_auth_performance_patterns(self) -> None:
        """Test auth performance patterns."""
        auth = FlextAuth()
        start_time = time.time()
        test_user_data = self._TestDataHelper.create_test_user_data()
        for i in range(10):
            result = auth.register_user(
                username=f"user_{i}",
                email=f"user_{i}@example.com",
                password=test_user_data["password"],
            )
            tm.that(result, is_=r)
            tm.that(result.success, eq=True)
        end_time = time.time()
        tm.that(end_time - start_time, lt=30.0)

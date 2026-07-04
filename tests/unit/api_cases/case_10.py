"""FlextAuth API test case group 10."""

from __future__ import annotations

import time

from flext_tests import r

from flext_auth import FlextAuth
from tests.models import m
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper
from tests.utilities import u


class TestsFlextAuthApiCase10:
    """FlextAuth API case group 10."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_flext_auth_error_handling(self) -> None:
        """Test auth module error handling patterns."""
        auth = FlextAuth()
        result = auth.register_user(username="", email="invalid_email", password="")
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.authenticate_user("invalid_user", "invalid_password")
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.identity_service.identity_manager.get_user_by_username(
            "non_existent_user",
        )
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)
        u.Tests.Matchers.that((result.error or "").lower(), has="not found")

    def test_flext_auth_with_flext_tests(self) -> None:
        """Test auth functionality with flext_tests infrastructure."""
        auth = FlextAuth()
        test_user_data = {
            "username": "flext_test_user",
            "email": "flext_test@example.com",
            "password": "TestPassword123!",
        }
        test_auth_data = {"username": "flext_test_user", "password": "TestPassword123!"}
        result = auth.register_user(
            username=test_user_data["username"],
            email=test_user_data["email"],
            password=test_user_data["password"],
        )
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)
        result = auth.authenticate_user(
            test_auth_data["username"],
            test_auth_data["password"],
        )
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_docstring(self) -> None:
        """Test that FlextAuth has proper docstring."""
        u.Tests.Matchers.that(FlextAuth.__doc__, none=False)
        u.Tests.Matchers.that(len((FlextAuth.__doc__ or "").strip()) > 0, eq=True)

    def test_flext_auth_with_real_data(self) -> None:
        """Test auth functionality with realistic data scenarios."""
        auth = FlextAuth()
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
        for user_data in realistic_users:
            result = auth.register_user(
                username=user_data["username"],
                email=user_data["email"],
                password=user_data["password"],
                roles=[user_data["role"]] if "role" in user_data else None,
            )
            u.Tests.Matchers.that(result, is_=r)
            u.Tests.Matchers.that(result.success, eq=True)
        for user_data in realistic_users:
            result = auth.authenticate_user(
                user_data["username"],
                user_data["password"],
            )
            u.Tests.Matchers.that(result, is_=r)
            u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_integration_patterns(self) -> None:
        """Test auth integration patterns — token ops succeed as expected."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        u.Tests.Matchers.that(register_result, is_=r, ok=True)
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        u.Tests.Matchers.that(auth_result, is_=r, ok=True)
        authenticated_identity = auth_result.value
        u.Tests.Matchers.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=authenticated_identity.unique_id)
        u.Tests.Matchers.that(token_result, is_=r, ok=True)

    def test_flext_auth_performance_patterns(self) -> None:
        """Test auth performance patterns."""
        auth = FlextAuth()
        start_time = time.time()
        test_user_data = self._TestDataHelper.create_test_user_data()
        for i in range(10):
            result = auth.register_user(
                username=f"user_{i}",
                email=f"user_{i}@example.com",
                password=str(test_user_data["password"]),
            )
            u.Tests.Matchers.that(result, is_=r)
            u.Tests.Matchers.that(result.success, eq=True)
        end_time = time.time()
        u.Tests.Matchers.that(end_time - start_time, lt=30.0)


__all__: list[str] = ["TestsFlextAuthApiCase10"]

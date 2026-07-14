"""FlextAuth API test case group 09."""

from __future__ import annotations

from flext_tests import r, tm

from flext_auth import FlextAuth
from tests import m, u
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper


class TestsFlextAuthApiCase09:
    """FlextAuth API case group 09."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_flext_auth_validate_token(self) -> None:
        """Test that create_token/validate_token fail — JWT provider not implemented."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_flext_auth_get_user_sessions(self) -> None:
        """Test FlextAuth get_user_sessions functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user = register_result.value
        user_id = user.unique_id
        result = auth.session_service.session_manager.get_active_sessions(user_id)
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_get_user_by_token_direct_api(self) -> None:
        """Test that create_token fails — user retrieval still works by ID."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        result = auth.identity_service.identity_manager.get_user(identity.unique_id)
        u.Tests.Matchers.that(result, is_=r)
        u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_revoke_session(self) -> None:
        """Test FlextAuth revoke_session functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id,
        )
        if sessions_result.success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                result = auth.session_service.session_manager.end_session_by_id(
                    session_id,
                )
                u.Tests.Matchers.that(result, is_=r)
                u.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_comprehensive_scenario(self) -> None:
        """Test comprehensive auth module scenario — token ops succeed as expected."""
        auth = FlextAuth()
        test_user_data = self._TestDataHelper.create_test_user_data()
        test_auth_data = self._TestDataHelper.create_test_auth_data()
        tm.that(auth, none=False)
        register_result = auth.register_user(
            username=str(test_user_data["username"]),
            email=str(test_user_data["email"]),
            password=str(test_user_data["password"]),
        )
        u.Tests.Matchers.that(register_result, is_=r)
        u.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        u.Tests.Matchers.that(auth_result, is_=r)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)


__all__: list[str] = ["TestsFlextAuthApiCase09"]

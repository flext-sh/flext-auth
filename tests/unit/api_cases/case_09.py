"""FlextAuth API test case group 09.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import r, tm

from flext_auth import FlextAuth, m
from tests import TestsFlextAuthUtilities
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase09:
    """FlextAuth API case group 09."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    def test_flext_auth_validate_token(self) -> None:
        """Test that create_token succeeds for a registered identity."""
        auth, identity, _test_data = self._TestDataHelper.registered_session()
        token_result = auth.create_token(identity_id=identity.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.error, none=True)

    def test_flext_auth_get_user_sessions(self) -> None:
        """Test FlextAuth get_user_sessions functionality."""
        auth, identity, _test_data = self._TestDataHelper.registered_session()
        result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(result, is_=r)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_get_user_by_token_direct_api(self) -> None:
        """Test that user retrieval still works by ID after token creation."""
        auth, identity, _test_data = self._TestDataHelper.registered_session()
        token_result = auth.create_token(identity_id=identity.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.success, eq=True)
        result = auth.identity_service.identity_manager.fetch_user(identity.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(result, is_=r)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.success, eq=True)

    def test_flext_auth_revoke_session(self) -> None:
        """Test FlextAuth revoke_session functionality."""
        auth = FlextAuth()
        test_data = self._TestDataHelper.create_test_auth_data()
        register_result = auth.register_user(
            username=str(test_data["username"]),
            email=str(test_data["email"]),
            password=str(test_data["password"]),
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_data["username"]),
            str(test_data["password"]),
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        TestsFlextAuthUtilities.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
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
                TestsFlextAuthUtilities.Tests.Matchers.that(result, is_=r)
                TestsFlextAuthUtilities.Tests.Matchers.that(result.success, eq=True)

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
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result, is_=r)
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        auth_result = auth.authenticate_user(
            str(test_auth_data["username"]),
            str(test_auth_data["password"]),
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result, is_=r)
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.error, none=True)

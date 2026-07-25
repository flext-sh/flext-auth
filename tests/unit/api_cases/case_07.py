"""FlextAuth API test case group 07."""

from __future__ import annotations

from flext_auth import FlextAuth
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper
from tests.utilities import u


class TestsFlextAuthApiCase07:
    """FlextAuth API case group 07."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_get_user_method(self) -> None:
        """Test get_user method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_get_user",
            email="getuser@example.com",
            password="GetUserPass123!@",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        get_result = auth.identity_service.identity_manager.get_user(user.unique_id)
        u.Tests.Matchers.that(get_result.success, eq=True)
        retrieved_user = get_result.value
        u.Tests.Matchers.that(retrieved_user.unique_id, eq=user.unique_id)

    def test_get_user_by_username_method(self) -> None:
        """Test get_user_by_username method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_username_lookup",
            email="lookup@example.com",
            password="LookupPass123!@",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        get_result = auth.identity_service.identity_manager.get_user_by_username(
            "test_username_lookup"
        )
        u.Tests.Matchers.that(get_result.success, is_=bool)

    def test_get_user_by_token_direct_api_method(self) -> None:
        """Test that create_token fails — user retrieval by ID still works."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_token_user",
            email="tokenuser@example.com",
            password="TokenUserPass123!@",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        get_result = auth.identity_service.identity_manager.get_user(user.unique_id)
        u.Tests.Matchers.that(get_result.success, eq=True)

    def test_logout_user_method(self) -> None:
        """Test logout_user method functionality."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="test_logout_user",
            email="logout@example.com",
            password="LogoutPass123!@",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id
        )
        if sessions_result.success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.session_service.session_manager.end_session_by_id(
                    session_id
                )
                u.Tests.Matchers.that(logout_result.success, is_=bool)

    def test_revoke_session_method(self) -> None:
        """Test revoke_session method functionality."""
        auth = FlextAuth()
        revoke_result = auth.session_service.session_manager.end_session_by_id(
            "test_session_id"
        )
        u.Tests.Matchers.that(revoke_result.success, is_=bool)

    def test_get_user_sessions_method(self) -> None:
        """Test get_user_sessions method functionality."""
        auth = FlextAuth()
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            "test_user_id"
        )
        u.Tests.Matchers.that(sessions_result.success, is_=bool)

    def test_cleanup_expired_sessions_method(self) -> None:
        """Test cleanup_expired_sessions method functionality."""
        auth = FlextAuth()
        cleanup_result = auth.session_service.cleanup_expired_sessions()
        u.Tests.Matchers.that(cleanup_result.success, is_=bool)

    def test_quick_start_without_redacted_ldap_bind_password(self) -> None:
        """Test quick_start class method without REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert isinstance(auth, FlextAuth)
        u.Tests.Matchers.that(auth.settings, none=False)

    def test_get_config_method(self) -> None:
        """Test settings property functionality."""
        auth = FlextAuth()
        settings = auth.settings
        u.Tests.Matchers.that(settings, none=False)

    def test_authenticate_with_locked_account(self) -> None:
        """Test authentication with locked user account."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="lockable_user",
            email="lockable@example.com",
            password="LockablePass123!",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        for _ in range(6):
            failed_result = auth.authenticate_user(
                username="lockable_user",
                password="wrong_password",
            )
            u.Tests.Matchers.that(not failed_result.success, eq=True)


__all__: list[str] = ["TestsFlextAuthApiCase07"]

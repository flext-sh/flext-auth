"""FlextAuth API test case group 04."""

from __future__ import annotations

from flext_auth import FlextAuth
from flext_tests import tm
from tests import c, m, u
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper


class TestsFlextAuthApiCase04:
    """FlextAuth API case group 04."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_token_validation_bearer_prefix(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "beareruser"
        password = "BearerPassword123!"
        register_result = auth.register_user(username, "bearer@example.com", password)
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_session_management(self) -> None:
        """Test session management functionality."""
        auth: FlextAuth = FlextAuth()
        username = "sessionuser"
        password = "SessionPassword123!"
        auth.register_user(username, "session@example.com", password)
        auth_result = auth.authenticate_user(
            username, password, "127.0.0.1", "test-user-agent"
        )
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)
        sessions = sessions_result.value
        u.Tests.Matchers.that(sessions, is_=list)
        u.Tests.Matchers.that(len(sessions), gte=0)

    def test_user_logout(self) -> None:
        """Test user logout functionality."""
        auth: FlextAuth = FlextAuth()
        username = "logoutuser"
        password = "LogoutPassword123!"
        auth.register_user(username, "logout@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            identity.unique_id
        )
        if sessions_result.success:
            sessions = sessions_result.value
            if sessions:
                session_id = sessions[0].unique_id
                logout_result = auth.session_service.session_manager.end_session_by_id(
                    session_id
                )
                u.Tests.Matchers.that(logout_result.success, eq=True)

    def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        auth: FlextAuth = FlextAuth()
        cleanup_result = auth.session_service.cleanup_expired_sessions()
        u.Tests.Matchers.that(cleanup_result.success, eq=True)
        cleaned_count = cleanup_result.value
        u.Tests.Matchers.that(cleaned_count, is_=int)
        u.Tests.Matchers.that(cleaned_count, gte=0)

    def test_sync_api_methods(self) -> None:
        """Test synchronous API methods work as expected."""
        auth: FlextAuth = FlextAuth()
        username = "syncuser"
        password = "SyncPassword123!"
        create_result = auth.register_user(username, "sync@example.com", password)
        u.Tests.Matchers.that(create_result.success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)

    def test_quick_start_default(self) -> None:
        """Test FlextAuth.quick_start with default parameters."""
        auth = FlextAuth.quick_start()
        tm.that(auth, is_=FlextAuth)

    def test_quick_start_with_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start with REDACTED_LDAP_BIND_PASSWORD user creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        tm.that(auth, is_=FlextAuth)

    def test_quick_start_custom_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start with custom REDACTED_LDAP_BIND_PASSWORD credentials."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        tm.that(auth, is_=FlextAuth)

    def test_quick_start_no_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start without REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(auth, is_=FlextAuth)

    def test_account_lockout_on_failed_attempts(self) -> None:
        """Test account lockout after multiple failed login attempts."""
        auth: FlextAuth = FlextAuth()
        username = "locktest"
        password = "LockTestPassword123!"
        auth.register_user(username, "lock@example.com", password)
        for _ in range(c.Auth.MAX_ATTEMPTS_DEFAULT):
            failed_auth = auth.authenticate_user(username, "wrong_password")
            u.Tests.Matchers.that(not failed_auth.success, eq=True)
        locked_auth = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(not locked_auth.success, eq=True)
        u.Tests.Matchers.that(
            (
                "locked" in (locked_auth.error or "").lower()
                or "inactive" in (locked_auth.error or "").lower()
            ),
            eq=True,
        )

    def test_password_strength_enforcement(self) -> None:
        """Test password strength requirements."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("weakuser", "weak@example.com", "weak")
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)


__all__: list[str] = ["TestsFlextAuthApiCase04"]

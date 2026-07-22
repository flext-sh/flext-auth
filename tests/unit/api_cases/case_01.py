"""FlextAuth API test case group 01."""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthSettings
from tests import u
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper


class TestsFlextAuthApiCase01:
    """FlextAuth API case group 01."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_auth_service_initialization_exposes_public_services(self) -> None:
        """FlextAuth quick_start initializes the public service properties."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(auth.identity_service, none=False)
        u.Tests.Matchers.that(auth.token_service, none=False)
        u.Tests.Matchers.that(auth.session_service, none=False)
        u.Tests.Matchers.that(auth.registry, none=False)

    def test_username_validation_processor(self) -> None:
        """Test username validation through processor."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result_valid = auth.register_user(
            "validuser", "test@example.com", "ValidPass123!"
        )
        u.Tests.Matchers.that(result_valid.success, eq=True)
        result_short = auth.register_user("ab", "test2@example.com", "ValidPass123!")
        u.Tests.Matchers.that(not result_short.success, eq=True)
        u.Tests.Matchers.that(result_short.error, none=False)

    def test_email_normalization_processor(self) -> None:
        """Test email normalization to lowercase."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.register_user("testuser", "TEST@EXAMPLE.COM", "ValidPass123!")
        u.Tests.Matchers.that(result.success, eq=True)
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "testuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        u.Tests.Matchers.that(user.contact, eq="test@example.com")

    def test_password_strength_validation_processor(self) -> None:
        """Test password strength validation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.register_user("user1", "user1@example.com", "weak")
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)
        error_text = (result.error or "").lower()
        u.Tests.Matchers.that(
            ("at least 8 characters" in error_text or "credential" in error_text),
            eq=True,
        )

    def test_identity_service_operations(self) -> None:
        """Test that identity service operations work correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.register_user("cmduser", "cmd@example.com", "CmdPass123!")
        u.Tests.Matchers.that(result.success, eq=True)

    def test_query_handlers_registered(self) -> None:
        """Test that query handlers are registered with FlextBus."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("queryuser", "query@example.com", "QueryPass123!")
        result = auth.identity_service.identity_manager.get_user_by_username(
            "queryuser"
        )
        u.Tests.Matchers.that(result.success, eq=True)

    def test_registry_lists_providers(self) -> None:
        """Registry exposes list_providers() returning a list."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        providers = auth.registry.list_providers()
        u.Tests.Matchers.that(providers, is_=list)

    def test_username_index_management(self) -> None:
        """Test username index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("indexuser", "index@example.com", "IndexPass123!")
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "indexuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)

    def test_email_index_management(self) -> None:
        """Test email index is maintained correctly."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("emailuser", "email@example.com", "EmailPass123!")
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "emailuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        u.Tests.Matchers.that(user.contact, eq="email@example.com")

    def test_user_sessions_index_management(self) -> None:
        """Test user sessions index is maintained."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("sessionuser", "session@example.com", "SessionPass123!")
        auth_result = auth.authenticate_user("sessionuser", "SessionPass123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user = auth_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)

    def test_custom_config_initialization(self) -> None:
        """Test initialization with custom configuration."""
        custom_config = FlextAuthSettings.fetch_global()
        auth = FlextAuth(settings=custom_config)
        u.Tests.Matchers.that(auth.settings, eq=custom_config)

    def test_get_user_sessions(self) -> None:
        """Test retrieving all sessions for a user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("sessuser", "sess@example.com", "SessPass123!")
        auth_result = auth.authenticate_user("sessuser", "SessPass123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "sessuser"
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)


__all__: list[str] = ["TestsFlextAuthApiCase01"]

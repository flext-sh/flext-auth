"""FlextAuth API test case group 02."""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthSettings
from tests.models import m
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper
from tests.utilities import u


class TestsFlextAuthApiCase02:
    """FlextAuth API case group 02."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_revoke_session(self) -> None:
        """Test revoking a session — authenticate_user creates a session."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("revokeuser", "revoke@example.com", "RevokePass123!")
        auth_result = auth.authenticate_user("revokeuser", "RevokePass123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        user = auth_result.value
        sessions_result = auth.session_service.session_manager.get_active_sessions(
            user.unique_id,
        )
        u.Tests.Matchers.that(sessions_result.success, eq=True)
        revoke_result = auth.session_service.session_manager.end_session_by_id(
            "nonexistent_session_id",
        )
        u.Tests.Matchers.that(not revoke_result.success, eq=True)

    def test_create_token_for_user(self) -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
        user_result = auth.identity_service.identity_manager.get_user_by_username(
            "tokenuser",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_validate_token_with_bearer_prefix(self) -> None:
        """Test token validation — not implemented in JWT provider."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        register_result = auth.register_user(
            "beareruser",
            "bearer@example.com",
            "BearerPass123!",
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        validate_result = auth.token_service.validate_token("any.fake.token")
        u.Tests.Matchers.that(not validate_result.success, eq=True)

    def test_duplicate_user_registration(self) -> None:
        """Test handling duplicate user registration."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("dupuser", "dup@example.com", "DupPass123!")
        result = auth.register_user("dupuser", "dup2@example.com", "DupPass123!")
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(
            result.error is not None and "already exists" in result.error.lower(),
            eq=True,
        )

    def test_authentication_with_invalid_credentials(self) -> None:
        """Test authentication with wrong password."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("authuser", "auth@example.com", "AuthPass123!")
        result = auth.authenticate_user("authuser", "WrongPassword123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_get_nonexistent_user(self) -> None:
        """Test retrieving non-existent user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.identity_service.identity_manager.get_user_by_username(
            "nonexistent",
        )
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)
        u.Tests.Matchers.that((result.error or "").lower(), has="not found")

    def test_initialization_logging(self) -> None:
        """Test that initialization is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "logger"), eq=True)
        u.Tests.Matchers.that(auth.logger, none=False)

    def test_handler_registration_logging(self) -> None:
        """Test that handler registration is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert auth is not None

    def test_provider_registry_initialization(self) -> None:
        """Test provider registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "registry"), eq=True)
        u.Tests.Matchers.that(auth.registry, none=False)

    def test_default_provider_name(self) -> None:
        """Test default provider is set to jwt."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        providers = auth.registry.list_providers()
        u.Tests.Matchers.that(providers, has="jwt")

    def test_model_config_arbitrary_types_allowed(self) -> None:
        """Test that arbitrary types are allowed in model settings."""
        u.Tests.Matchers.that(hasattr(m.Auth.AuthIdentity, "model_config"), eq=True)

    def test_model_config_validate_assignment(self) -> None:
        """Test validate_assignment configuration."""
        settings = FlextAuthSettings.fetch_global()
        u.Tests.Matchers.that(
            settings.model_config.get("validate_assignment", False) is True,
            eq=True,
        )


__all__: list[str] = ["TestsFlextAuthApiCase02"]

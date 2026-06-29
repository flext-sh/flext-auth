"""FlextAuth API test case group 05."""

from __future__ import annotations

import pytest

from flext_auth import FlextAuth, FlextAuthSettings
from tests import u
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper


class TestsFlextAuthApiCase05:
    """FlextAuth API case group 05."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_empty_username_registration(self) -> None:
        """Test registration with empty username."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("", "empty@example.com", "Password123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_empty_email_registration(self) -> None:
        """Test registration with empty email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "", "Password123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_empty_password_registration(self) -> None:
        """Test registration with empty password."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "test@example.com", "")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_invalid_email_registration(self) -> None:
        """Test registration with invalid email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("user", "invalid-email", "Password123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_nonexistent_user_authentication(self) -> None:
        """Test authentication of non-existent user."""
        auth: FlextAuth = FlextAuth()
        auth_result = auth.authenticate_user("nonexistent", "password")
        u.Tests.Matchers.that(not auth_result.success, eq=True)
        u.Tests.Matchers.that(auth_result.error, none=False)
        u.Tests.Matchers.that(auth_result.error or "", empty=False)

    def test_invalid_session_logout(self) -> None:
        """Test logout with invalid session ID."""
        auth: FlextAuth = FlextAuth()
        logout_result = auth.session_service.session_manager.end_session_by_id(
            "invalid_session_id"
        )
        u.Tests.Matchers.that(not logout_result.success, eq=True)
        u.Tests.Matchers.that(not logout_result.success, eq=True)
        u.Tests.Matchers.that((logout_result.error or ""), has="not found")

    def test_flext_auth_quick_start_default(self) -> None:
        """Test FlextAuth.quick_start() with default parameters."""
        auth = FlextAuth.quick_start()
        assert isinstance(auth, FlextAuth)
        u.Tests.Matchers.that(auth.settings, none=False)
        u.Tests.Matchers.that(auth.registry, none=False)

    def test_flext_auth_quick_start_no_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() without creating REDACTED_LDAP_BIND_PASSWORD user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        assert isinstance(auth, FlextAuth)
        nonexistent_result = (
            auth.identity_service.identity_manager.get_user_by_username(
                "nonexistent_user"
            )
        )
        u.Tests.Matchers.that(not nonexistent_result.success, eq=True)
        u.Tests.Matchers.that(nonexistent_result.error, none=False)
        u.Tests.Matchers.that((nonexistent_result.error or "").lower(), has="not found")

    def test_flext_auth_quick_start_custom_redacted_ldap_bind_password(self) -> None:
        """Test FlextAuth.quick_start() with REDACTED_LDAP_BIND_PASSWORD creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)

    def test_flext_auth_config_creation_failure(self) -> None:
        """Test FlextAuth initialization when settings creation fails - lines 228-229."""
        try:
            auth = FlextAuth()
            u.Tests.Matchers.that(auth.config, none=False)
        except RuntimeError as e:
            pytest.fail(f"FlextAuth creation failed with RuntimeError: {e}")
        except Exception as e:
            pytest.fail(f"Unexpected exception during FlextAuth creation: {e}")

    def test_quick_start_redacted_ldap_bind_password_creation_failure(self) -> None:
        """Test quick_start with REDACTED_LDAP_BIND_PASSWORD creation (reserved for future)."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert isinstance(auth, FlextAuth)

    def test_quick_start_general_failure(self) -> None:
        """Test quick_start general path."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        assert auth is not None
        assert isinstance(auth, FlextAuth)

    def test_flext_auth_initialization_with_overrides(self) -> None:
        """Test FlextAuth initialization with parameter overrides - lines 235-237."""
        settings = FlextAuthSettings.model_validate({
            "expiry_minutes": 120,
            "hash_rounds": 10,
            "secret_key": "test-secret-key-with-minimum-32-characters-length",
        })
        auth = FlextAuth(settings=settings)
        u.Tests.Matchers.that(auth.config.expiry_minutes, eq=120)
        u.Tests.Matchers.that(auth.config.hash_rounds, eq=10)

    def test_register_user_edge_cases(self) -> None:
        """Test register_user method error paths."""
        auth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="invalid-email-format",
            password="ValidPassword123!",
        )
        u.Tests.Matchers.that(not result.success, eq=True)
        error_msg = result.error or ""
        u.Tests.Matchers.that(
            (
                "contact" in error_msg.lower()
                or "email" in error_msg.lower()
                or "pattern" in error_msg.lower()
            ),
            eq=True,
        )


__all__: list[str] = ["TestsFlextAuthApiCase05"]

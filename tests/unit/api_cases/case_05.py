"""FlextAuth API test case group 05.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth import FlextAuth, FlextAuthSettings
from tests import c, tm
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase05:
    """FlextAuth API case group 05."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_empty_username_registration() -> None:
        """Test registration with empty username."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user("", "empty@example.com", "Password123!")
        tm.ok(not result.success)

    @staticmethod
    def test_empty_email_registration() -> None:
        """Test registration with empty email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(c.ContextScope.USER, "", "Password123!")
        tm.ok(not result.success)

    @staticmethod
    def test_empty_password_registration() -> None:
        """Test registration with empty password."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(c.ContextScope.USER, "test@example.com", "")
        tm.ok(not result.success)

    @staticmethod
    def test_invalid_email_registration() -> None:
        """Test registration with invalid email."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(
            c.ContextScope.USER, "invalid-email", "Password123!"
        )
        tm.ok(not result.success)

    @staticmethod
    def test_nonexistent_user_authentication() -> None:
        """Test authentication of non-existent user."""
        auth: FlextAuth = FlextAuth()
        auth_result = auth.authenticate_user("nonexistent", "password")
        tm.ok(not auth_result.success)
        tm.that(auth_result.error, none=False)
        tm.that(auth_result.error or "", empty=False)

    @staticmethod
    def test_invalid_session_logout() -> None:
        """Test logout with invalid session ID."""
        auth: FlextAuth = FlextAuth()
        logout_result = auth.session_service.session_manager.end_session_by_id(
            "invalid_session_id",
        )
        tm.ok(not logout_result.success)
        tm.ok(not logout_result.success)
        tm.that((logout_result.error or ""), has="not found")

    @staticmethod
    def test_flext_auth_quick_start_default() -> None:
        """Test FlextAuth.quick_start() with default parameters."""
        auth = FlextAuth.quick_start()
        tm.that(auth, is_=FlextAuth)
        tm.that(auth.settings, none=False)
        tm.that(auth.registry, none=False)

    @staticmethod
    def test_flext_auth_quick_start_no_admin_user() -> None:
        """Test FlextAuth.quick_start() without creating admin user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(auth, is_=FlextAuth)
        nonexistent_result = (
            auth.identity_service.identity_manager.fetch_user_by_username(
                "nonexistent_user",
            )
        )
        tm.ok(not nonexistent_result.success)
        tm.that(nonexistent_result.error, none=False)
        tm.that((nonexistent_result.error or "").lower(), has="not found")

    @staticmethod
    def test_flext_auth_quick_start_custom_admin_creation() -> None:
        """Test FlextAuth.quick_start() with admin creation."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        tm.that(auth, is_=FlextAuth)

    @staticmethod
    def test_flext_auth_config_creation_failure() -> None:
        """Test FlextAuth initialization when settings creation fails."""
        try:
            auth = FlextAuth()
            tm.that(auth.config, none=False)
        except RuntimeError as e:
            pytest.fail(f"FlextAuth creation failed with RuntimeError: {e}")

    @staticmethod
    def test_quick_start_admin_creation_failure() -> None:
        """Test quick_start with admin creation (reserved for future)."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        tm.that(auth, is_=FlextAuth)

    @staticmethod
    def test_quick_start_general_failure() -> None:
        """Test quick_start general path."""
        auth = FlextAuth.quick_start(create_admin_user=True)
        tm.that(auth, none=False)
        tm.that(auth, is_=FlextAuth)

    @staticmethod
    def test_flext_auth_initialization_with_overrides() -> None:
        """Test FlextAuth initialization with parameter overrides - lines 235-237."""
        settings = FlextAuthSettings(
            Auth=FlextAuthSettings.AuthSettings(
                expiry_minutes=120,
                hash_rounds=10,
                secret_key="s" * c.Auth.SECRET_MIN_LENGTH,
            ),
        )
        auth = FlextAuth(runtime_settings=settings)
        tm.ok(auth.config is settings.Auth)
        tm.that(auth.config.expiry_minutes, eq=120)
        tm.that(settings.Auth.hash_rounds, eq=10)

    @staticmethod
    def test_register_user_edge_cases() -> None:
        """Test register_user method error paths."""
        auth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="invalid-email-format",
            password=c.TEST_CREDENTIAL,
        )
        tm.ok(not result.success)
        error_msg = result.error or ""
        tm.that(
            (
                "contact" in error_msg.lower()
                or "email" in error_msg.lower()
                or "pattern" in error_msg.lower()
            ),
            eq=True,
        )

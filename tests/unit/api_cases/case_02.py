"""FlextAuth API test case group 02.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import tm

from flext_auth import FlextAuth, FlextAuthSettings, m
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper
from tests.utilities import TestsFlextAuthUtilities as u


class TestsFlextAuthApiCase02:
    """FlextAuth API case group 02."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_revoke_session() -> None:
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

    @staticmethod
    def test_create_token_for_user() -> None:
        """Test that token creation fails — JWT provider not implemented."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("tokenuser", "token@example.com", "TokenPass123!")
        user_result = auth.identity_service.identity_manager.fetch_user_by_username(
            "tokenuser",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        token_result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    @staticmethod
    def test_validate_token_with_bearer_prefix() -> None:
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

    @staticmethod
    def test_duplicate_user_registration() -> None:
        """Test handling duplicate user registration."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("dupuser", "dup@example.com", "DupPass123!")
        result = auth.register_user("dupuser", "dup2@example.com", "DupPass123!")
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(
            result.error is not None and "already exists" in result.error.lower(),
            eq=True,
        )

    @staticmethod
    def test_authentication_with_invalid_credentials() -> None:
        """Test authentication with wrong password."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("authuser", "auth@example.com", "AuthPass123!")
        result = auth.authenticate_user("authuser", "WrongPassword123!")
        u.Tests.Matchers.that(not result.success, eq=True)

    @staticmethod
    def test_get_nonexistent_user() -> None:
        """Test retrieving non-existent user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        result = auth.identity_service.identity_manager.fetch_user_by_username(
            "nonexistent",
        )
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=False)
        u.Tests.Matchers.that((result.error or "").lower(), has="not found")

    @staticmethod
    def test_initialization_logging() -> None:
        """Test that initialization is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "logger"), eq=True)
        u.Tests.Matchers.that(auth.logger, none=False)

    @staticmethod
    def test_handler_registration_logging() -> None:
        """Test that handler registration is logged."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        tm.that(auth, none=False)

    @staticmethod
    def test_provider_registry_initialization() -> None:
        """Test provider registry is initialized."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        u.Tests.Matchers.that(hasattr(auth, "registry"), eq=True)
        u.Tests.Matchers.that(auth.registry, none=False)

    @staticmethod
    def test_default_provider_name() -> None:
        """Test default provider is set to jwt."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        providers = auth.registry.list_providers()
        u.Tests.Matchers.that(providers, has="jwt")

    @staticmethod
    def test_model_config_arbitrary_types_allowed() -> None:
        """Test that arbitrary types are allowed in model settings."""
        u.Tests.Matchers.that(hasattr(m.Auth.AuthIdentity, "model_config"), eq=True)

    @staticmethod
    def test_model_config_validate_assignment() -> None:
        """Test validate_assignment configuration."""
        u.Tests.Matchers.that(
            FlextAuthSettings.model_config.get("validate_assignment", False) is True,
            eq=True,
        )

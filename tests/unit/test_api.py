"""Behavioral tests for the FlextAuth public API facade.

These tests exercise only the observable public contract of ``FlextAuth``
(registration, credential authentication, token minting, service exposure and
singleton semantics) through its published methods and properties. No private
attribute, internal collaborator, or implementation detail is asserted.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from flext_tests import tm

from flext_auth import (
    FlextAuth,
    FlextAuthIdentityService,
    FlextAuthRegistry,
    FlextAuthSessionService,
    FlextAuthSettings,
    t,
)
from tests import c


class TestsFlextAuthApi:
    """Public-contract behavior of the FlextAuth API facade."""

    pytestmark = pytest.mark.usefixtures("reset_auth_singleton")

    @staticmethod
    def _fresh_auth() -> FlextAuth:
        """Return an isolated FlextAuth with no seeded admin user."""
        return FlextAuth.quick_start(create_admin_user=False)

    @staticmethod
    def test_quick_start_exposes_public_service_properties() -> None:
        """quick_start yields a facade whose public services are available."""
        auth = TestsFlextAuthApi._fresh_auth()

        # The payload vocabulary is deliberately closed over comparable
        # shapes, so service availability asserts the published contract
        # types through the payload-free ``is_`` probe (arbitrary domain
        # objects are not payload leaves by design).
        tm.that(auth.identity_service, is_=FlextAuthIdentityService)
        tm.that(auth.session_service, is_=FlextAuthSessionService)
        tm.that(auth.session_service, is_=FlextAuthSessionService)
        tm.that(auth.registry, is_=FlextAuthRegistry)

    @staticmethod
    def test_settings_property_returns_injected_settings() -> None:
        """The settings property returns the exact settings instance supplied."""
        settings = FlextAuthSettings.model_validate({})

        auth = FlextAuth(settings=settings)

        assert auth.settings is settings

    @staticmethod
    def test_fetch_global_returns_the_same_singleton_instance() -> None:
        """fetch_global is idempotent: repeated calls return one instance."""
        first = FlextAuth.fetch_global()
        second = FlextAuth.fetch_global()

        assert first is second

    @staticmethod
    def test_registry_list_providers_returns_a_list() -> None:
        """registry.list_providers exposes a list contract."""
        auth = TestsFlextAuthApi._fresh_auth()

        providers = auth.registry.list_providers()

        tm.that(providers, is_=list)

    @staticmethod
    def test_register_user_succeeds_and_returns_identity() -> None:
        """Registering a valid user succeeds and returns the new identity."""
        auth = TestsFlextAuthApi._fresh_auth()

        result = auth.register_user("validuser", "user@example.com", c.TEST_CREDENTIAL)

        tm.ok(result)
        identity = result.value
        tm.that(identity.name, eq="validuser")
        assert identity.unique_id

    @staticmethod
    def test_register_user_normalizes_email_to_lowercase() -> None:
        """Email contact is normalized to lowercase on the returned identity."""
        auth = TestsFlextAuthApi._fresh_auth()

        result = auth.register_user("mixeduser", "MixED@Example.COM", c.TEST_CREDENTIAL)

        tm.ok(result)
        tm.that(result.value.contact, eq="mixed@example.com")

    @staticmethod
    @pytest.mark.parametrize(
        ("roles", "role"),
        [(None, "user"), (["admin"], None), (None, None)],
    )
    def test_register_user_accepts_role_variants(
        roles: list[str] | None,
        role: str | None,
    ) -> None:
        """Registration succeeds whether role, roles, or neither is provided."""
        auth = TestsFlextAuthApi._fresh_auth()

        result = auth.register_user(
            "roleuser",
            "roleuser@example.com",
            c.TEST_CREDENTIAL,
            roles=roles,
            role=role,
        )

        tm.ok(result)

    @staticmethod
    def test_register_user_rejects_too_short_username() -> None:
        """A username below the minimum length fails with an error message."""
        auth = TestsFlextAuthApi._fresh_auth()

        result = auth.register_user("ab", "short@example.com", c.TEST_CREDENTIAL)

        tm.fail(result)
        assert result.error

    @staticmethod
    def test_register_user_rejects_weak_password() -> None:
        """A password that is too short fails validation with an error."""
        auth = TestsFlextAuthApi._fresh_auth()

        result = auth.register_user("weakuser", "weak@example.com", "weak")

        tm.fail(result)
        error_text = (result.error or "").lower()
        assert "at least 8 characters" in error_text or "credential" in error_text

    @staticmethod
    def test_register_user_rejects_duplicate_username() -> None:
        """Registering an already-taken username fails; the first one wins."""
        auth = TestsFlextAuthApi._fresh_auth()

        first = auth.register_user("dupuser", "dup1@example.com", c.TEST_CREDENTIAL)
        second = auth.register_user("dupuser", "dup2@example.com", c.TEST_CREDENTIAL)

        tm.ok(first)
        tm.fail(second)
        assert second.error

    @staticmethod
    def test_authenticate_with_valid_credentials_returns_identity() -> None:
        """Authenticating a registered user with the right password succeeds."""
        auth = TestsFlextAuthApi._fresh_auth()
        auth.register_user("authuser", "auth@example.com", c.TEST_CREDENTIAL)

        result = auth.authenticate({
            "username": "authuser",
            "password": c.TEST_CREDENTIAL,
        })

        tm.ok(result)
        tm.that(result.value.name, eq="authuser")

    @staticmethod
    def test_authenticate_with_wrong_password_fails() -> None:
        """Authenticating with an incorrect password fails with an error."""
        auth = TestsFlextAuthApi._fresh_auth()
        auth.register_user("authuser", "auth@example.com", c.TEST_CREDENTIAL)

        result = auth.authenticate({"username": "authuser", "password": "w" + "0" * 12})

        tm.fail(result)
        assert result.error

    @staticmethod
    @pytest.mark.parametrize(
        "credentials",
        [
            {"username": "", "password": ""},
            {"username": "someone", "password": ""},
            {"username": "", "password": c.TEST_CREDENTIAL},
        ],
    )
    def test_authenticate_rejects_missing_credentials(
        credentials: t.StrMapping,
    ) -> None:
        """Empty username or password fails before any provider dispatch."""
        auth = TestsFlextAuthApi._fresh_auth()

        result = auth.authenticate(credentials)

        tm.fail(result)
        tm.that((result.error or ""), has="username and password required")

    @staticmethod
    def test_create_token_for_registered_user_returns_jwt() -> None:
        """create_token mints a three-segment JWT for a valid identity id."""
        auth = TestsFlextAuthApi._fresh_auth()
        registered = auth.register_user(
            "tokenuser",
            "token@example.com",
            c.TEST_CREDENTIAL,
        )
        tm.ok(registered)

        token_result = auth.create_token(registered.value.unique_id)

        tm.ok(token_result)
        tm.that(token_result.value.count("."), eq=2)

    @staticmethod
    def test_create_token_rejects_empty_identity_id() -> None:
        """create_token fails for an empty identity id with a clear error."""
        auth = TestsFlextAuthApi._fresh_auth()

        result = auth.create_token("")

        tm.fail(result)
        tm.that(result.error, eq="Identity ID must be a non-empty string")

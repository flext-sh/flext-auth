"""Behavioral tests for the FlextAuth public API facade.

These tests exercise only the observable public contract of ``FlextAuth``
(registration, credential authentication, token minting, service exposure and
instance-scoped registries) through its published methods and properties. No private
attribute, internal collaborator, or implementation detail is asserted.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Mapping

import pytest

from flext_auth import FlextAuth, FlextAuthSettings
from tests import c, p, tm


class TestsFlextAuthApi:
    """Public-contract behavior of the FlextAuth API facade."""

    pytestmark = pytest.mark.usefixtures("reset_auth_singleton")

    @staticmethod
    def test_quick_start_exposes_public_service_properties() -> None:
        """quick_start yields a facade whose public services are available."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        tm.that(auth.identity_service, is_=p.Auth.IdentityService)
        tm.that(auth.session_service, is_=p.Auth.SessionService)
        tm.that(auth.registry, is_=p.Registry)

    @staticmethod
    def test_settings_property_returns_injected_settings() -> None:
        """The settings property returns the exact settings instance supplied."""
        settings = FlextAuthSettings()

        auth = FlextAuth(runtime_settings=settings)

        def has_injected_settings(value: p.Auth.Settings) -> bool:
            return value is settings

        tm.that(auth.settings, where=has_injected_settings)

    @staticmethod
    def test_constructors_own_independent_registries() -> None:
        """Constructors are isolated; sharing requires explicit registry injection."""
        first = FlextAuth()
        second = FlextAuth()

        def is_independent_registry(value: p.Registry) -> bool:
            return value is not second.registry

        tm.that(first.registry, where=is_independent_registry)

    @staticmethod
    def test_list_providers_exposes_the_registered_names() -> None:
        """The public sequence names providers reachable through the same facade."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        providers = auth.list_providers()

        expected = tm.ok(auth.registry.list_plugins(c.Auth.REGISTRY_PROVIDERS_CATEGORY))
        tm.that(providers, eq=expected)
        for name in providers:
            tm.ok(auth.fetch_provider(name))

    @staticmethod
    def test_register_user_succeeds_and_returns_identity() -> None:
        """Registering a valid user succeeds and returns the new identity."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        result = auth.register_user("validuser", "user@example.com", c.TEST_CREDENTIAL)

        tm.ok(result)
        identity = result.value
        tm.that(identity.name, eq="validuser")
        tm.that(identity.unique_id, truth=True)

    @staticmethod
    def test_register_user_normalizes_email_to_lowercase() -> None:
        """Email contact is normalized to lowercase on the returned identity."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        result = auth.register_user("mixeduser", "MixED@Example.COM", c.TEST_CREDENTIAL)

        tm.ok(result)
        tm.that(result.value.contact, eq="mixed@example.com")

    @staticmethod
    @pytest.mark.parametrize(
        ("roles", "role"),
        [(None, c.ContextScope.USER), (["admin"], None), (None, None)],
    )
    def test_register_user_accepts_role_variants(
        roles: list[str] | None,
        role: str | None,
    ) -> None:
        """Registration succeeds whether role, roles, or neither is provided."""
        auth = FlextAuth.quick_start(create_admin_user=False)

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
        auth = FlextAuth.quick_start(create_admin_user=False)

        result = auth.register_user("ab", "short@example.com", c.TEST_CREDENTIAL)

        tm.fail(result)
        tm.that(result.error, truth=True)

    @staticmethod
    def test_register_user_rejects_weak_password() -> None:
        """A password that is too short fails validation with an error."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        result = auth.register_user("weakuser", "weak@example.com", "weak")

        tm.fail(result)
        error_text = (result.error or "").lower()

        def mentions_failure_reason(value: str) -> bool:
            return "at least 8 characters" in value or "credential" in value

        tm.that(error_text, where=mentions_failure_reason)

    @staticmethod
    def test_register_user_rejects_duplicate_username() -> None:
        """Registering an already-taken username fails; the first one wins."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        first = auth.register_user("dupuser", "dup1@example.com", c.TEST_CREDENTIAL)
        second = auth.register_user("dupuser", "dup2@example.com", c.TEST_CREDENTIAL)

        tm.ok(first)
        tm.fail(second)
        tm.that(second.error, truth=True)

    @staticmethod
    def test_authenticate_with_valid_credentials_returns_identity() -> None:
        """Authenticating a registered user with the right password succeeds."""
        auth = FlextAuth.quick_start(create_admin_user=False)
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
        auth = FlextAuth.quick_start(create_admin_user=False)
        auth.register_user("authuser", "auth@example.com", c.TEST_CREDENTIAL)

        result = auth.authenticate({
            "username": "authuser",
            "password": "w" + c.ParserBooleanToken.ZERO * 12,
        })

        tm.fail(result)
        tm.that(result.error, truth=True)

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
        credentials: Mapping[str, str],
    ) -> None:
        """Empty username or password fails before any provider dispatch."""
        auth = FlextAuth.quick_start(create_admin_user=False)

        result = auth.authenticate(credentials)

        tm.fail(result)
        tm.that((result.error or ""), has="username and password required")

    @staticmethod
    def test_create_token_for_registered_user_returns_jwt() -> None:
        """create_token mints a three-segment JWT for a valid identity id."""
        auth = FlextAuth.quick_start(create_admin_user=False)
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
        auth = FlextAuth.quick_start(create_admin_user=False)

        result = auth.create_token("")

        tm.fail(result)
        tm.that(result.error, eq="Identity ID must be a non-empty string")

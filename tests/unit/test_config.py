"""Behavioral tests for FlextAuthSettings public contract.

Exercises observable settings behavior (defaults, validation, immutability,
env overrides, secret handling) and the token flow that consumes the
configured expiry, all through the public API only. Every project field is
accessed through the canonical nested namespace ``settings.Auth.*``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth import (
    FlextAuth,
    FlextAuthSettings,
    c,
    m,
    t,
)
from tests.utilities import u

pytestmark = pytest.mark.usefixtures("reset_auth_singleton")


class TestsFlextAuthConfig:
    """Behavioral contract for FlextAuthSettings and its consumers."""

    @pytest.fixture
    def settings(self) -> FlextAuthSettings:
        """Provide the current global settings instance."""
        return FlextAuthSettings.fetch_global()

    def test_default_settings_expose_positive_expiry_and_string_algorithm(
        self,
        settings: FlextAuthSettings,
    ) -> None:
        """Default settings satisfy the documented value invariants."""
        u.Tests.Matchers.that(settings, is_=FlextAuthSettings)
        u.Tests.Matchers.that(settings.Auth.expiry_minutes, gt=0)
        u.Tests.Matchers.that(settings.Auth.session_expiry_minutes, gt=0)
        u.Tests.Matchers.that(settings.Auth.max_sessions_per_user, gt=0)
        u.Tests.Matchers.that(settings.Auth.algorithm, is_=str)

    @pytest.mark.parametrize(
        ("field_name", "expected"),
        [
            ("algorithm", c.Auth.DEFAULT_JWT_ALGORITHM),
            ("issuer", c.Auth.DEFAULT_ISSUER),
            ("audience", c.Auth.DEFAULT_AUDIENCE),
            ("expiry_minutes", c.Auth.DEFAULT_JWT_EXPIRY_MINUTES),
            ("session_expiry_minutes", c.Auth.DEFAULT_SESSION_EXPIRY_MINUTES),
            ("max_sessions_per_user", c.Auth.DEFAULT_MAX_SESSIONS_PER_USER),
            ("hash_rounds", c.Auth.DEFAULT_HASH_ROUNDS),
        ],
    )
    def test_field_defaults_match_declared_constants(
        self,
        field_name: str,
        expected: str | int,
    ) -> None:
        """Freshly constructed settings default each field to its constant."""
        settings = FlextAuthSettings()
        u.Tests.Matchers.that(getattr(settings.Auth, field_name), eq=expected)

    def test_clone_returns_new_instance_and_leaves_original_unchanged(
        self,
        settings: FlextAuthSettings,
    ) -> None:
        """Cloning produces an independent copy with the requested override."""
        original_expiry = settings.Auth.expiry_minutes

        clone = settings.clone(Auth={"expiry_minutes": original_expiry + 5})

        u.Tests.Matchers.that(clone is settings, eq=False)
        u.Tests.Matchers.that(clone.Auth.expiry_minutes, eq=original_expiry + 5)
        u.Tests.Matchers.that(settings.Auth.expiry_minutes, eq=original_expiry)

    def test_model_copy_applies_multiple_overrides(
        self,
        settings: FlextAuthSettings,
    ) -> None:
        """model_copy overrides all requested fields in the returned copy."""
        updated = settings.model_copy(
            update={
                "Auth": settings.Auth.model_copy(
                    update={"expiry_minutes": 60, "hash_rounds": 12},
                ),
            },
        )
        u.Tests.Matchers.that(updated.Auth.expiry_minutes, eq=60)
        u.Tests.Matchers.that(updated.Auth.hash_rounds, eq=12)

    @pytest.mark.parametrize(
        "overrides",
        [
            {"hash_rounds": c.Auth.HASH_ROUNDS_MIN - 1},
            {"hash_rounds": c.Auth.HASH_ROUNDS_MAX + 1},
            {"expiry_minutes": 0},
            {"session_expiry_minutes": -1},
            {"secret_key": "short"},
        ],
    )
    def test_construction_rejects_out_of_contract_values(
        self,
        overrides: dict[str, str | int],
    ) -> None:
        """Values outside the declared bounds fail model validation."""
        with pytest.raises(m.ValidationError):
            FlextAuthSettings.model_validate({"Auth": overrides})

    def test_auth_secret_property_wraps_secret_key_as_secret_str(self) -> None:
        """auth_secret exposes the secret_key as a SecretStr round-trip."""
        secret_value = "x" * (c.Auth.SECRET_MIN_LENGTH + 4)

        settings = FlextAuthSettings.model_validate(
            {"Auth": {"secret_key": secret_value}},
        )

        u.Tests.Matchers.that(settings.Auth.auth_secret, is_=t.SecretStr)
        u.Tests.Matchers.that(
            settings.Auth.auth_secret.get_secret_value(),
            eq=settings.Auth.secret_key,
        )

    def test_secret_str_input_is_normalized_to_plain_string_field(self) -> None:
        """A SecretStr passed for secret_key is stored as its plain value."""
        raw = "y" * (c.Auth.SECRET_MIN_LENGTH + 8)

        settings = FlextAuthSettings.model_validate(
            {"Auth": {"secret_key": t.SecretStr(raw)}},
        )

        u.Tests.Matchers.that(settings.Auth.secret_key, is_=str)
        u.Tests.Matchers.that(settings.Auth.secret_key, eq=raw)

    def test_environment_prefix_overrides_defaults(
        self,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        """FLEXT_AUTH_ prefixed env vars override the field defaults."""
        monkeypatch.setenv("FLEXT_AUTH_AUTH__EXPIRY_MINUTES", "123")
        monkeypatch.setenv("FLEXT_AUTH_AUTH__ALGORITHM", "HS512")

        settings = FlextAuthSettings()

        u.Tests.Matchers.that(settings.Auth.expiry_minutes, eq=123)
        u.Tests.Matchers.that(settings.Auth.algorithm, eq="HS512")

    def test_create_token_fails_for_unknown_identity(
        self,
        settings: FlextAuthSettings,
    ) -> None:
        """Token creation fails for an unregistered identity."""
        auth = FlextAuth(settings=settings)

        result = auth.create_token(identity_id="missing-user")

        u.Tests.Matchers.that(result.success, eq=False)
        u.Tests.Matchers.that(result.error, none=False)
        u.Tests.Matchers.that("user" in (result.error or "").lower(), eq=True)

    @pytest.mark.parametrize("identity_id", ["", "   "])
    def test_create_token_rejects_blank_identity(
        self,
        settings: FlextAuthSettings,
        identity_id: str,
    ) -> None:
        """Blank identity ids are rejected before any token is produced."""
        auth = FlextAuth(settings=settings)

        result = auth.create_token(identity_id=identity_id)

        u.Tests.Matchers.that(result.success, eq=False)
        u.Tests.Matchers.that(result.error, none=False)

    def test_create_token_succeeds_for_registered_identity(
        self,
        settings: FlextAuthSettings,
    ) -> None:
        """A registered identity yields a well-formed JWT via the public API."""
        auth = FlextAuth(settings=settings)

        register_result = auth.register_user(
            "config-token-user",
            "config-token-user@example.com",
            "ConfigTokenPass123!",
        )
        u.Tests.Matchers.that(register_result.success, eq=True)

        token_result = auth.create_token(
            identity_id=register_result.value.unique_id,
        )

        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.value, is_=str)
        token_text: str = token_result.value
        u.Tests.Matchers.that(len(token_text), gt=0)
        u.Tests.Matchers.that(token_text.count("."), eq=2)

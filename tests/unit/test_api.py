"""Behavioral tests for the FlextAuth public API facade.

These tests exercise only the observable public contract of ``FlextAuth``
(registration, credential authentication, token minting, service exposure and
singleton semantics) through its published methods and properties. No private
attribute, internal collaborator, or implementation detail is asserted.
"""

from __future__ import annotations

import pytest

from flext_auth import FlextAuth, FlextAuthSettings

pytestmark = pytest.mark.usefixtures("reset_auth_singleton")

_VALID_PASSWORD = "ValidPass123!"


def _fresh_auth() -> FlextAuth:
    """Return an isolated FlextAuth with no seeded admin user."""
    return FlextAuth.quick_start(create_admin_user=False)


class TestsFlextAuthApi:
    """Public-contract behavior of the FlextAuth API facade."""

    def test_quick_start_exposes_public_service_properties(self) -> None:
        """quick_start yields a facade whose public services are available."""
        auth = _fresh_auth()

        assert auth.identity_service is not None
        assert auth.token_service is not None
        assert auth.session_service is not None
        assert auth.registry is not None

    def test_settings_property_returns_injected_settings(self) -> None:
        """The settings property returns the exact settings instance supplied."""
        settings = FlextAuthSettings()

        auth = FlextAuth(settings=settings)

        assert auth.settings is settings

    def test_fetch_global_returns_the_same_singleton_instance(self) -> None:
        """fetch_global is idempotent: repeated calls return one instance."""
        first = FlextAuth.fetch_global()
        second = FlextAuth.fetch_global()

        assert first is second

    def test_registry_list_providers_returns_a_list(self) -> None:
        """registry.list_providers exposes a list contract."""
        auth = _fresh_auth()

        providers = auth.registry.list_providers()

        assert isinstance(providers, list)

    def test_register_user_succeeds_and_returns_identity(self) -> None:
        """Registering a valid user succeeds and returns the new identity."""
        auth = _fresh_auth()

        result = auth.register_user("validuser", "user@example.com", _VALID_PASSWORD)

        assert result.success
        identity = result.value
        assert identity.name == "validuser"
        assert identity.unique_id

    def test_register_user_normalizes_email_to_lowercase(self) -> None:
        """Email contact is normalized to lowercase on the returned identity."""
        auth = _fresh_auth()

        result = auth.register_user("mixeduser", "MixED@Example.COM", _VALID_PASSWORD)

        assert result.success
        assert result.value.contact == "mixed@example.com"

    @pytest.mark.parametrize(
        ("roles", "role"),
        [
            (None, "user"),
            (["admin"], None),
            (None, None),
        ],
    )
    def test_register_user_accepts_role_variants(
        self,
        roles: list[str] | None,
        role: str | None,
    ) -> None:
        """Registration succeeds whether role, roles, or neither is provided."""
        auth = _fresh_auth()

        result = auth.register_user(
            "roleuser",
            "roleuser@example.com",
            _VALID_PASSWORD,
            roles=roles,
            role=role,
        )

        assert result.success

    def test_register_user_rejects_too_short_username(self) -> None:
        """A username below the minimum length fails with an error message."""
        auth = _fresh_auth()

        result = auth.register_user("ab", "short@example.com", _VALID_PASSWORD)

        assert not result.success
        assert result.error

    def test_register_user_rejects_weak_password(self) -> None:
        """A password that is too short fails validation with an error."""
        auth = _fresh_auth()

        result = auth.register_user("weakuser", "weak@example.com", "weak")

        assert not result.success
        error_text = (result.error or "").lower()
        assert "at least 8 characters" in error_text or "credential" in error_text

    def test_register_user_rejects_duplicate_username(self) -> None:
        """Registering an already-taken username fails; the first one wins."""
        auth = _fresh_auth()

        first = auth.register_user("dupuser", "dup1@example.com", _VALID_PASSWORD)
        second = auth.register_user("dupuser", "dup2@example.com", _VALID_PASSWORD)

        assert first.success
        assert not second.success
        assert second.error

    def test_authenticate_with_valid_credentials_returns_identity(self) -> None:
        """Authenticating a registered user with the right password succeeds."""
        auth = _fresh_auth()
        auth.register_user("authuser", "auth@example.com", _VALID_PASSWORD)

        result = auth.authenticate(
            {"username": "authuser", "password": _VALID_PASSWORD},
        )

        assert result.success
        assert result.value.name == "authuser"

    def test_authenticate_with_wrong_password_fails(self) -> None:
        """Authenticating with an incorrect password fails with an error."""
        auth = _fresh_auth()
        auth.register_user("authuser", "auth@example.com", _VALID_PASSWORD)

        result = auth.authenticate(
            {"username": "authuser", "password": "WrongPass123!"},
        )

        assert not result.success
        assert result.error

    @pytest.mark.parametrize(
        "credentials",
        [
            {"username": "", "password": ""},
            {"username": "someone", "password": ""},
            {"username": "", "password": _VALID_PASSWORD},
        ],
    )
    def test_authenticate_rejects_missing_credentials(
        self,
        credentials: dict[str, str],
    ) -> None:
        """Empty username or password fails before any provider dispatch."""
        auth = _fresh_auth()

        result = auth.authenticate(credentials)

        assert not result.success
        assert "username and password required" in (result.error or "")

    def test_create_token_for_registered_user_returns_jwt(self) -> None:
        """create_token mints a three-segment JWT for a valid identity id."""
        auth = _fresh_auth()
        registered = auth.register_user(
            "tokenuser",
            "token@example.com",
            _VALID_PASSWORD,
        )
        assert registered.success

        token_result = auth.create_token(registered.value.unique_id)

        assert token_result.success
        assert token_result.value.count(".") == 2

    def test_create_token_rejects_empty_identity_id(self) -> None:
        """create_token fails for an empty identity id with a clear error."""
        auth = _fresh_auth()

        result = auth.create_token("")

        assert not result.success
        assert result.error == "Identity ID must be a non-empty string"


__all__: list[str] = ["TestsFlextAuthApi"]

"""Real-world token flow tests for the flext-auth public API.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import io
from datetime import UTC, datetime

from flext_auth import FlextAuth, FlextAuthSettings, u as auth_u
from flext_auth.providers import FlextAuthKeycloakProvider
from tests import c, m, p, t, tm, u


class TestsFlextAuthSessionRealFlows:
    """Token flow tests using only FlextAuth public API."""

    pytestmark = c.Tests.MARK.usefixtures("reset_auth_singleton")

    @staticmethod
    def test_settings_and_bootstrap_use_existing_runtime_contracts() -> None:
        """The actual API runtime supplies auth settings through structural ports."""
        configured = FlextAuthSettings()
        auth = FlextAuth(runtime_settings=configured)
        tm.that(auth.settings, is_=p.Auth.Settings)
        tm.that(auth.runtime_bootstrap_options(), is_=p.RuntimeBootstrapOptions)
        tm.that(auth.settings.Auth.expiry_minutes, eq=configured.Auth.expiry_minutes)
        tm.that(
            auth.settings.Auth.session_expiry_minutes,
            eq=configured.Auth.session_expiry_minutes,
        )

    @staticmethod
    def test_token_audits_omit_credentials_and_keep_results() -> None:
        """Real runtime audit events contain decisions, never token fragments."""
        previous_options = u.logging_options()
        previous_settings = u.logging_settings()
        configured = FlextAuthSettings(log_level="DEBUG")
        stream = io.StringIO()
        try:
            u.configure_structlog(
                runtime_settings=configured,
                settings=m.StructlogOptions(
                    handlers=(u.create_logging_handler(stream=stream),),
                    async_logging=False,
                ),
            )
            auth = FlextAuth(runtime_settings=configured)
            identity = tm.ok(
                auth.register_user(
                    "audit-user",
                    "audit@example.com",
                    c.TEST_CREDENTIAL,
                )
            )
            token = tm.ok(auth.create_token(identity.unique_id))
            refreshed = tm.ok(auth.session_service.refresh_token(token))
            tm.ok(auth.session_service.validate_token(refreshed.token))
            marker = "sensitive-credential-marker"
            tm.fail(auth.session_service.refresh_token(marker))
            tm.fail(auth.session_service.validate_token(marker))
            audit = stream.getvalue()
            tm.that(audit, has="Token creation successful")
            tm.that(audit, has="Token refresh successful")
            tm.that(audit, has="Token validation")
            tm.that(audit, has=identity.unique_id)
            for material in (token, refreshed.token, marker, "sensitive", token[:9]):
                tm.ok(material not in audit)
            tm.that(refreshed.user_id, eq=identity.unique_id)
            tm.that(refreshed, is_=p.Auth.Session)
        finally:
            u.configure_structlog(
                settings=previous_options,
                runtime_settings=previous_settings,
            )

    @staticmethod
    def test_identity_extras_preserve_supported_payload_values() -> None:
        """Validate actual identity inputs without replacing normalization code."""
        instant = datetime.now(UTC)
        role = c.Auth.RoleTypes.USER.value
        extras = m.Auth.UserIdentityExtras.model_validate({
            "roles": [role],
            "permissions": ["profile.read"],
            "failed_attempts": c.ParserBooleanToken.ONE,
            "locked_until": instant,
            "last_access": instant.isoformat(),
        })
        tm.that(extras.roles, has=role)
        tm.that(extras.permissions, has="profile.read")
        tm.that(extras.failed_attempts, eq=1)
        tm.that(extras.locked_until, eq=instant)
        tm.that(extras.last_access, eq=instant)

    @staticmethod
    def test_create_token_for_registered_user() -> None:
        """Test create token for registered user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="token-flow-user",
            email="token-flow-user@example.com",
            password=c.TEST_CREDENTIAL,
        )
        tm.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        tm.ok(token_result)
        token_value = token_result.value
        tm.that(token_value, is_=str)
        tm.that(token_value.count("."), eq=2)

    @staticmethod
    def test_validate_token_after_creation() -> None:
        """Test validate token after creation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="token-validate-user",
            email="token-validate-user@example.com",
            password=c.TEST_CREDENTIAL,
        )
        tm.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        tm.ok(token_result)

        validation_result = auth.session_service.validate_token(token_result.value)
        tm.ok(validation_result)

    @staticmethod
    def test_validate_token_rejects_invalid_token() -> None:
        """Test validate token rejects invalid token."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        invalid_result = auth.session_service.validate_token("invalid.jwt.token")
        tm.fail(invalid_result.success)

    @staticmethod
    def test_authenticate_user_and_create_token_sequence() -> None:
        """Test authenticate user and create token sequence."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        username = "sequence-user"
        password = c.TEST_CREDENTIAL
        register_result = auth.register_user(
            username=username,
            email="sequence-user@example.com",
            password=password,
        )
        tm.ok(register_result)

        authenticated = auth.authenticate_user(username, password)
        tm.ok(authenticated)

        token_result = auth.create_token(identity_id=authenticated.value.unique_id)
        tm.ok(token_result)

    @staticmethod
    def test_create_token_preserves_lookup_failure() -> None:
        """A missing identity keeps its lookup diagnostics through token creation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        missing = "missing-token-user"
        lookup = auth.session_service.user_manager.fetch_user(missing)
        tm.fail(lookup, code=c.ErrorCode.NOT_FOUND_ERROR)

        rejected = auth.create_token(missing)

        tm.fail(rejected, code=lookup.error_code)
        tm.that(rejected.error, eq=lookup.error)
        tm.that(rejected.error_data, eq=lookup.error_data)
        tm.that(rejected.exception, is_=type(lookup.exception))


class TestsFlextAuthKeycloakProvider:
    """Keycloak provider behavior through its public contract."""

    @staticmethod
    def test_keycloak_declares_oidc_and_keycloak_support() -> None:
        """The provider advertises its Keycloak/OIDC capabilities."""
        provider = FlextAuthKeycloakProvider()

        tm.that(provider.supports(), contains="keycloak")
        tm.that(provider.supports(), contains="oidc")
        tm.that(provider.rfc_version, eq="OpenID Connect Core 1.0")

    @staticmethod
    def test_keycloak_derives_canonical_scopes_from_groups_and_roles() -> None:
        """Realm groups and roles map to the canonical access scopes."""
        claims: t.Auth.TokensClaimMap = {
            "sub": "user-1",
            "groups": ["cosmos-qas-viewer", "cosmos-editor"],
        }

        scopes = tm.ok(FlextAuthKeycloakProvider.scopes_from_claims(claims))

        tm.that(scopes, eq=frozenset({"read", "write"}))

    @staticmethod
    def test_keycloak_validates_a_real_signed_token() -> None:
        """A signed Keycloak token is accepted and its claims are readable."""
        secret = c.TEST_CREDENTIAL * 3
        payload: t.Auth.TokensClaimMap = {"sub": "user-1", "groups": ["cosmos-admin"]}
        token = tm.ok(auth_u.Auth.encode_token(payload, secret))
        provider = FlextAuthKeycloakProvider(
            settings={"secret_key": secret, "algorithm": "HS256"}
        )

        tm.ok(provider.validate(token))
        claims = tm.ok(provider.claims(token))

        tm.that(claims.get("sub"), eq="user-1")
        tm.that(
            tm.ok(FlextAuthKeycloakProvider.scopes_from_claims(claims)),
            eq=frozenset({"admin"}),
        )

    @staticmethod
    def test_keycloak_rejects_an_invalid_token() -> None:
        """An invalid bearer token is rejected by the shared JWT owner."""
        provider = FlextAuthKeycloakProvider(
            settings={"secret_key": c.TEST_CREDENTIAL * 3, "algorithm": "HS256"}
        )

        tm.fail(provider.validate("invalid.jwt.token"))

    @staticmethod
    def test_keycloak_authorize_accepts_a_sufficient_scope() -> None:
        """A bearer credential with the required scope is authorized."""
        secret = c.TEST_CREDENTIAL * 3
        token = tm.ok(
            auth_u.Auth.encode_token(
                {"sub": "user-1", "groups": ["cosmos-editor"]}, secret
            )
        )
        provider = FlextAuthKeycloakProvider(
            settings={"secret_key": secret, "algorithm": "HS256"}
        )

        granted = tm.ok(
            provider.authorize(
                {"authorization": f"Bearer {token}"}, required_scope="write"
            )
        )

        tm.that(granted, contains="write")

    @staticmethod
    def test_keycloak_authorize_rejects_a_missing_bearer() -> None:
        """Absent bearer metadata is rejected before any token work."""
        provider = FlextAuthKeycloakProvider(
            settings={"secret_key": c.TEST_CREDENTIAL * 3, "algorithm": "HS256"}
        )

        tm.fail(provider.authorize({}, required_scope="read"))

    @staticmethod
    def test_keycloak_authorize_rejects_an_insufficient_scope() -> None:
        """A reader cannot perform a write operation."""
        secret = c.TEST_CREDENTIAL * 3
        token = tm.ok(
            auth_u.Auth.encode_token(
                {"sub": "user-1", "groups": ["cosmos-viewer"]}, secret
            )
        )
        provider = FlextAuthKeycloakProvider(
            settings={"secret_key": secret, "algorithm": "HS256"}
        )

        tm.fail(
            provider.authorize(
                {"authorization": f"Bearer {token}"}, required_scope="write"
            )
        )

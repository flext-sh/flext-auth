"""Keycloak provider behavior through the composed FlextAuth runtime.

Every token is RS256-signed by a real realm whose signing keys are served over
HTTP, so verification runs the production key-fetch and signature path.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import (
    FlextAuth,
    FlextAuthSettings,
    TestsFlextAuthFixtures,
    c,
    config,
    p,
    t,
    tm,
    u,
)


class TestsFlextAuthKeycloakProvider:
    """Keycloak realm verification and scope enforcement via the composition root."""

    pytestmark = c.Tests.MARK.usefixtures("reset_auth_singleton")

    @staticmethod
    def authorizer(
        realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> p.Auth.ScopedTokenAuthorizer:
        """Compose FlextAuth for the realm and resolve its Keycloak provider.

        Returns:
            The Keycloak provider resolved through the composition root.

        """
        auth = FlextAuth(runtime_settings=realm.settings())
        provider = tm.ok(auth.fetch_provider(c.Auth.ProviderTypes.KEYCLOAK.value))
        if not isinstance(provider, p.Auth.ScopedTokenAuthorizer):
            tm.reject()
        return provider

    @staticmethod
    def test_unconfigured_realm_is_not_composed() -> None:
        """Without a realm issuer the composition root registers no Keycloak."""
        unconfigured = FlextAuthSettings(
            Auth=FlextAuthSettings.AuthSettings(
                Keycloak=FlextAuthSettings.AuthSettings.KeycloakSettings()
            )
        )
        tm.fail(
            FlextAuth(runtime_settings=unconfigured).fetch_provider(
                c.Auth.ProviderTypes.KEYCLOAK.value
            )
        )

    @staticmethod
    def test_issuer_without_audience_is_rejected() -> None:
        """A realm issuer configured without its audience fails at the boundary."""
        with u.Tests.raises(c.ValidationError):
            FlextAuthSettings.AuthSettings.KeycloakSettings(
                issuer="https://realm.invalid/realms/flext"
            )

    @staticmethod
    def test_configured_realm_registers_keycloak(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A configured realm composes the provider with its capabilities."""
        provider = tm.ok(
            FlextAuth(runtime_settings=keycloak_realm.settings()).fetch_provider(
                c.Auth.ProviderTypes.KEYCLOAK.value
            )
        )
        tm.that(provider.supports(), contains=c.Auth.ProviderTypes.KEYCLOAK.value)
        tm.that(provider.supports(), contains=c.Auth.ProviderTypes.OIDC.value)

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("scope", "marker"),
        [
            (rule.scope, marker)
            for rule in config.Auth.keycloak.scope_rules
            for marker in rule.markers
        ],
        ids=str,
    )
    def test_each_rule_marker_grants_its_scope(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        scope: str,
        marker: str,
    ) -> None:
        """A group containing a rule's marker grants that rule's scope."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        bearer = keycloak_realm.bearer({"groups": [f"/team-{marker}"]})
        tm.that(
            tm.ok(provider.authorize(bearer, required_scope=scope)),
            contains=scope,
        )

    @staticmethod
    def test_realm_role_claim_grants_scope(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A realm role matches its rule marker case-insensitively."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[-1]
        bearer = keycloak_realm.bearer({
            "realm_access": {"roles": [rule.markers[0].upper()]}
        })
        tm.that(
            tm.ok(provider.authorize(bearer, required_scope=rule.scope)),
            contains=rule.scope,
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        "required_scope",
        [rule.scope for rule in config.Auth.keycloak.scope_rules],
        ids=str,
    )
    def test_superuser_scope_satisfies_any_required_scope(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        required_scope: str,
    ) -> None:
        """The configured superuser scope satisfies every rule's scope."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        policy = config.Auth.keycloak
        superuser_rule = next(
            rule for rule in policy.scope_rules if rule.scope == policy.superuser_scope
        )
        bearer = keycloak_realm.bearer({"groups": [superuser_rule.markers[0]]})
        tm.ok(provider.authorize(bearer, required_scope=required_scope))

    @staticmethod
    def test_insufficient_scope_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A name granting only a later rule's scope fails an earlier rule's scope."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        policy = config.Auth.keycloak
        granting, required = policy.scope_rules[-1], policy.scope_rules[0]
        bearer = keycloak_realm.bearer({"groups": [granting.markers[0]]})
        tm.fail(provider.authorize(bearer, required_scope=required.scope))

    @staticmethod
    def test_unmatched_names_are_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """Names matching no rule grant no scope and fail the default scope."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        tm.fail(provider.authorize(keycloak_realm.bearer({"groups": ["/unrelated"]})))

    @staticmethod
    def test_malformed_claims_fail_validation(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A groups claim violating the Keycloak contract fails loud."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        tm.fail(provider.authorize(keycloak_realm.bearer({"groups": "not-a-list"})))

    @staticmethod
    def test_expired_token_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """An expired realm token fails verification."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer(
            {"groups": [rule.markers[0]]}, lifetime_seconds=-60
        )
        tm.fail(provider.authorize(bearer, required_scope=rule.scope))

    @staticmethod
    def test_foreign_audience_and_issuer_are_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """Tokens minted for another client or realm fail verification."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        marker = rule.markers[0]
        tm.fail(
            provider.authorize(
                keycloak_realm.bearer({"groups": [marker], "aud": "another-client"}),
                required_scope=rule.scope,
            )
        )
        tm.fail(
            provider.authorize(
                keycloak_realm.bearer({
                    "groups": [marker],
                    "iss": f"{keycloak_realm.issuer}-other",
                }),
                required_scope=rule.scope,
            )
        )

    @staticmethod
    def test_unpublished_signing_key_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        foreign_realm_key: t.Tests.RealmSigningKey,
    ) -> None:
        """A token signed by a key the realm does not publish is rejected."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer(
            {"groups": [rule.markers[0]]}, signing_key=foreign_realm_key
        )
        tm.fail(provider.authorize(bearer, required_scope=rule.scope))

    @staticmethod
    def test_shared_secret_token_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """An HS256 token is outside the configured realm algorithms."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        configured = keycloak_realm.settings().Auth
        token = tm.ok(
            u.Auth.encode_token(
                {"iss": keycloak_realm.issuer, "aud": keycloak_realm.audience},
                configured.secret_key,
            )
        )
        tm.fail(provider.authorize(f"{c.Auth.AuthorizationSchemes.BEARER} {token}"))

    @staticmethod
    def test_missing_or_foreign_scheme_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """Only a Bearer credential is accepted."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(keycloak_realm)
        tm.fail(provider.authorize(""))
        tm.fail(provider.authorize("Basic opaque-credential"))

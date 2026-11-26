"""Keycloak provider behavior through the composed FlextAuth runtime.

Every token is signed by a real realm whose signing keys are served over HTTP,
so verification runs the production key-fetch and signature path. Each
rejection asserts the failure the owning check declares.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time

from tests import FlextAuth, FlextAuthSettings, c, config, p, t, tm, u
from tests.fixtures import TestsFlextAuthFixtures


class TestsFlextAuthKeycloakProvider:
    """Keycloak realm verification and scope enforcement via the composition root."""

    pytestmark = c.Tests.MARK.usefixtures("reset_auth_singleton")

    @staticmethod
    def authorizer(issuer: str, audience: str) -> p.Auth.ScopedTokenAuthorizer:
        """Compose FlextAuth for one realm and resolve its Keycloak provider.

        Returns:
            The Keycloak provider resolved through the composition root.

        """
        configured = FlextAuthSettings(
            Auth=FlextAuthSettings.AuthSettings(
                Keycloak=FlextAuthSettings.AuthSettings.KeycloakSettings(
                    issuer=issuer, audience=audience
                )
            )
        )
        auth = FlextAuth(runtime_settings=configured)
        provider = tm.ok(auth.fetch_provider(c.Auth.ProviderTypes.KEYCLOAK.value))
        if not isinstance(provider, p.Auth.ScopedTokenAuthorizer):
            tm.reject()
        return provider

    @staticmethod
    def realm_authorizer(
        realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> p.Auth.ScopedTokenAuthorizer:
        """Resolve the Keycloak provider composed for the served realm.

        Returns:
            The Keycloak provider bound to the realm issuer and audience.

        """
        return TestsFlextAuthKeycloakProvider.authorizer(realm.issuer, realm.audience)

    @staticmethod
    def first_rule() -> t.Auth.TokensClaimMap:
        """Return claims holding the first configured rule's first group.

        Returns:
            Claims that grant the first rule's scope.

        """
        return {"groups": [config.Auth.keycloak.scope_rules[0].groups[0]]}

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
    @c.Tests.MARK.parametrize(
        "issuer",
        [
            "https://realm.invalid/realms/flext",
            "http://realm.invalid/realms/flext",
        ],
        ids=str,
    )
    def test_realm_settings_reject_unsafe_or_incomplete_issuers(issuer: str) -> None:
        """An issuer without audience, or plain http off loopback, is rejected."""
        audience = "" if issuer.startswith("https") else "flext-test-client"
        with u.Tests.raises(c.ValidationError):
            FlextAuthSettings.AuthSettings.KeycloakSettings(
                issuer=issuer, audience=audience
            )

    @staticmethod
    def test_issuer_trailing_slash_is_normalized(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A configured trailing slash still verifies the realm's ``iss``."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(
            f"{keycloak_realm.issuer}/", keycloak_realm.audience
        )
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer(TestsFlextAuthKeycloakProvider.first_rule())
        tm.ok(provider.authorize(bearer, required_scope=rule.scope))

    @staticmethod
    def test_configured_realm_advertises_validation_without_refresh(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """The composed provider advertises Keycloak and OIDC validation only."""
        provider = tm.ok(
            FlextAuth(runtime_settings=keycloak_realm.settings()).fetch_provider(
                c.Auth.ProviderTypes.KEYCLOAK.value
            )
        )
        tm.that(provider.supports(), contains=c.Auth.ProviderTypes.KEYCLOAK.value)
        tm.that(provider.supports(), contains=c.Auth.ProviderTypes.OIDC.value)
        tm.that(provider.supports(), lacks=c.Auth.TokenTypes.REFRESH.value)

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("scope", "claims"),
        [
            *(
                (rule.scope, {"groups": [group]})
                for rule in config.Auth.keycloak.scope_rules
                for group in rule.groups
            ),
            *(
                (rule.scope, {"realm_access": {"roles": [role]}})
                for rule in config.Auth.keycloak.scope_rules
                for role in rule.roles
            ),
        ],
        ids=str,
    )
    def test_exact_group_or_role_grants_its_scope(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        scope: str,
        claims: t.Auth.TokensClaimMap,
    ) -> None:
        """An exactly held group path or realm role grants its rule's scope."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        granted = tm.ok(
            provider.authorize(keycloak_realm.bearer(claims), required_scope=scope)
        )
        tm.that(granted, contains=scope)

    @staticmethod
    @c.Tests.MARK.parametrize(
        "claims",
        [
            *(
                {"groups": [lookalike]}
                for group in config.Auth.keycloak.scope_rules[0].groups
                for lookalike in (
                    f"{group}/interns",
                    f"/no-{group.lstrip('/')}",
                    f"{group}-pending",
                    group.upper(),
                )
            ),
            *(
                {"realm_access": {"roles": [lookalike]}}
                for role in config.Auth.keycloak.scope_rules[0].roles
                for lookalike in (
                    f"default-roles-{role}",
                    f"{role}-request",
                    f"no-{role}",
                )
            ),
        ],
        ids=str,
    )
    def test_lookalike_names_grant_nothing(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        claims: t.Auth.TokensClaimMap,
    ) -> None:
        """Nested paths, prefixes and default realm roles never escalate."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        tm.fail(
            provider.authorize(
                keycloak_realm.bearer(claims), required_scope=rule.scope
            ),
            has=c.Auth.KEYCLOAK_MISSING_SCOPE,
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
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        policy = config.Auth.keycloak
        superuser_rule = next(
            rule for rule in policy.scope_rules if rule.scope == policy.superuser_scope
        )
        bearer = keycloak_realm.bearer({"groups": [superuser_rule.groups[0]]})
        tm.ok(provider.authorize(bearer, required_scope=required_scope))

    @staticmethod
    def test_audience_list_containing_the_client_is_accepted(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """Keycloak's list-valued ``aud`` is accepted when it names the client."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer({
            **TestsFlextAuthKeycloakProvider.first_rule(),
            "aud": [keycloak_realm.audience, "account"],
        })
        tm.ok(provider.authorize(bearer, required_scope=rule.scope))

    @staticmethod
    def test_unmatched_names_are_rejected_for_the_default_scope(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """Names matching no rule fail the configured default scope."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        tm.fail(
            provider.authorize(keycloak_realm.bearer({"groups": ["/unrelated"]})),
            has=f"{c.Auth.KEYCLOAK_MISSING_SCOPE} "
            f"{config.Auth.keycloak.default_required_scope!r}",
        )

    @staticmethod
    def test_malformed_claims_fail_validation(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A groups claim violating the Keycloak contract fails loud."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        tm.fail(
            provider.authorize(keycloak_realm.bearer({"groups": "not-a-list"})),
            has="Keycloak claim validation",
        )

    @staticmethod
    @c.Tests.MARK.parametrize(
        ("claims", "lifetime_seconds", "omit"),
        [
            ({}, -int(config.Auth.keycloak.leeway_seconds) - 60, ()),
            ({}, 300, ("exp",)),
            ({"aud": "another-client"}, 300, ()),
            ({"iss": "https://other.invalid/realms/x"}, 300, ()),
            (
                {
                    "nbf": int(time.time())
                    + int(config.Auth.keycloak.leeway_seconds)
                    + 3600
                },
                7200,
                (),
            ),
        ],
        ids=[
            "expired",
            "missing-exp",
            "foreign-audience",
            "foreign-issuer",
            "not-yet-valid",
        ],
    )
    def test_invalid_realm_tokens_are_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        claims: t.Auth.TokensClaimMap,
        lifetime_seconds: int,
        omit: tuple[str, ...],
    ) -> None:
        """Expired, unbounded, not-yet-valid and foreign aud/iss tokens fail."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer(
            {**TestsFlextAuthKeycloakProvider.first_rule(), **claims},
            lifetime_seconds=lifetime_seconds,
            omit=omit,
        )
        tm.fail(
            provider.authorize(bearer, required_scope=rule.scope),
            has=c.Auth.KEYCLOAK_REJECTED_CREDENTIAL,
        )

    @staticmethod
    def test_id_token_is_not_an_access_token(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A realm ID token for the same client is refused as a credential."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer({
            **TestsFlextAuthKeycloakProvider.first_rule(),
            "typ": "ID",
        })
        tm.fail(
            provider.authorize(bearer, required_scope=rule.scope),
            has=c.Auth.KEYCLOAK_NOT_ACCESS_CREDENTIAL,
        )

    @staticmethod
    def test_unpublished_signing_key_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        foreign_realm_key: t.Tests.RealmSigningKey,
    ) -> None:
        """A token under the realm key id but another key fails its signature."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer(
            TestsFlextAuthKeycloakProvider.first_rule(), signing_key=foreign_realm_key
        )
        tm.fail(
            provider.authorize(bearer, required_scope=rule.scope),
            has=c.Auth.KEYCLOAK_REJECTED_CREDENTIAL,
        )

    @staticmethod
    def test_unknown_key_id_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """A key id the realm does not publish is rejected as an invalid token."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = keycloak_realm.bearer(
            TestsFlextAuthKeycloakProvider.first_rule(), key_id="unpublished-key"
        )
        tm.fail(
            provider.authorize(bearer, required_scope=rule.scope),
            has=c.Auth.KEYCLOAK_REJECTED_CREDENTIAL,
        )

    @staticmethod
    def test_shared_secret_token_under_realm_key_id_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """HS256 under the realm key id fails the asymmetric algorithm policy."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        rule = config.Auth.keycloak.scope_rules[0]
        token = u.Tests.sign_shared_secret_token(
            keycloak_realm.access_claims(TestsFlextAuthKeycloakProvider.first_rule()),
            keycloak_realm.settings().Auth.secret_key,
            keycloak_realm.key_id,
        )
        tm.fail(
            provider.authorize(
                f"{c.Auth.AuthorizationSchemes.BEARER} {token}",
                required_scope=rule.scope,
            ),
            has=c.Auth.KEYCLOAK_REJECTED_CREDENTIAL,
        )

    @staticmethod
    def test_unreachable_signing_keys_are_reported_as_unavailable(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
        unreachable_realm_issuer: str,
    ) -> None:
        """A key-server outage is distinct from an invalid token."""
        provider = TestsFlextAuthKeycloakProvider.authorizer(
            unreachable_realm_issuer, keycloak_realm.audience
        )
        bearer = keycloak_realm.bearer({
            **TestsFlextAuthKeycloakProvider.first_rule(),
            "iss": unreachable_realm_issuer,
        })
        tm.fail(
            provider.authorize(bearer),
            has=c.Auth.KEYCLOAK_SIGNING_KEYS_UNAVAILABLE,
        )

    @staticmethod
    def test_missing_or_foreign_scheme_is_rejected(
        keycloak_realm: TestsFlextAuthFixtures.KeycloakRealm,
    ) -> None:
        """Only a Bearer credential is accepted."""
        provider = TestsFlextAuthKeycloakProvider.realm_authorizer(keycloak_realm)
        tm.fail(provider.authorize(""), has=c.Auth.KEYCLOAK_MISSING_BEARER)
        tm.fail(
            provider.authorize("Basic opaque-credential"),
            has=c.Auth.KEYCLOAK_MISSING_BEARER,
        )

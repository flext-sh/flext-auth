"""Keycloak provider behavior through the composed FlextAuth runtime.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import FlextAuth, FlextAuthSettings, c, config, p, t, tm, u


class TestsFlextAuthKeycloakProvider:
    """Keycloak token validation and scope enforcement via the composition root."""

    pytestmark = c.Tests.MARK.usefixtures("reset_auth_singleton")

    @staticmethod
    def composed() -> tuple[FlextAuthSettings, p.Auth.ScopedTokenAuthorizer]:
        """Compose FlextAuth and resolve its Keycloak provider capability.

        Returns:
            The runtime settings and the resolved scope authorizer.

        """
        configured = FlextAuthSettings()
        auth = FlextAuth(runtime_settings=configured)
        provider = tm.ok(auth.fetch_provider(c.Auth.ProviderTypes.KEYCLOAK.value))
        assert isinstance(provider, p.Auth.ScopedTokenAuthorizer)
        return configured, provider

    @staticmethod
    def bearer(configured: FlextAuthSettings, claims: t.Auth.TokensClaimMap) -> str:
        """Sign claims with the composed JWT settings as a Bearer header value.

        Returns:
            The ``Authorization`` header value carrying the signed token.

        """
        auth_settings = configured.Auth
        token = tm.ok(
            u.Auth.encode_token(
                {"sub": "realm-user", "aud": auth_settings.audience, **claims},
                auth_settings.secret_key,
                auth_settings.algorithm,
            )
        )
        return f"{c.Auth.AuthorizationSchemes.BEARER} {token}"

    @staticmethod
    def test_composition_root_registers_keycloak() -> None:
        """FlextAuth registers the Keycloak provider with its capabilities."""
        provider = tm.ok(
            FlextAuth().fetch_provider(c.Auth.ProviderTypes.KEYCLOAK.value)
        )
        tm.that(provider, is_=p.Auth.ScopedTokenAuthorizer)
        tm.that(provider.supports(), contains=c.Auth.ProviderTypes.KEYCLOAK.value)
        tm.that(provider.supports(), contains=c.Auth.ProviderTypes.OIDC.value)

    @staticmethod
    def test_group_claim_grants_the_first_rule_scope() -> None:
        """A group containing the first rule's marker grants that rule's scope."""
        configured, provider = TestsFlextAuthKeycloakProvider.composed()
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = TestsFlextAuthKeycloakProvider.bearer(
            configured, {"groups": [f"/team-{rule.markers[0]}"]}
        )
        granted = tm.ok(provider.authorize(bearer, required_scope=rule.scope))
        tm.that(granted, eq=frozenset({rule.scope}))

    @staticmethod
    def test_realm_role_claim_grants_scope() -> None:
        """A realm role containing a rule marker grants that rule's scope."""
        configured, provider = TestsFlextAuthKeycloakProvider.composed()
        rule = config.Auth.keycloak.scope_rules[0]
        bearer = TestsFlextAuthKeycloakProvider.bearer(
            configured, {"realm_access": {"roles": [rule.markers[0].upper()]}}
        )
        tm.that(
            tm.ok(provider.authorize(bearer, required_scope=rule.scope)),
            contains=rule.scope,
        )

    @staticmethod
    def test_superuser_scope_satisfies_any_required_scope() -> None:
        """The configured superuser scope satisfies every rule's scope."""
        configured, provider = TestsFlextAuthKeycloakProvider.composed()
        policy = config.Auth.keycloak
        superuser_rule = next(
            rule for rule in policy.scope_rules if rule.scope == policy.superuser_scope
        )
        bearer = TestsFlextAuthKeycloakProvider.bearer(
            configured, {"groups": [superuser_rule.markers[0]]}
        )
        for rule in policy.scope_rules:
            tm.ok(provider.authorize(bearer, required_scope=rule.scope))

    @staticmethod
    def test_unmatched_names_grant_nothing_and_are_rejected() -> None:
        """Names matching no rule grant no scope and fail the default scope."""
        configured, provider = TestsFlextAuthKeycloakProvider.composed()
        bearer = TestsFlextAuthKeycloakProvider.bearer(
            configured, {"groups": ["/unrelated-team"]}
        )
        tm.fail(provider.authorize(bearer))

    @staticmethod
    def test_malformed_claims_fail_validation() -> None:
        """A groups claim violating the Keycloak contract fails loud."""
        configured, provider = TestsFlextAuthKeycloakProvider.composed()
        bearer = TestsFlextAuthKeycloakProvider.bearer(
            configured, {"groups": "not-a-list"}
        )
        tm.fail(provider.authorize(bearer))

    @staticmethod
    def test_missing_or_foreign_scheme_is_rejected() -> None:
        """Only a Bearer credential is accepted."""
        _configured, provider = TestsFlextAuthKeycloakProvider.composed()
        tm.fail(provider.authorize(""))
        tm.fail(provider.authorize("Basic opaque-credential"))

    @staticmethod
    def test_invalid_signature_is_rejected() -> None:
        """A token not signed by the configured secret is rejected."""
        _configured, provider = TestsFlextAuthKeycloakProvider.composed()
        tm.fail(
            provider.authorize(
                f"{c.Auth.AuthorizationSchemes.BEARER} invalid.jwt.token"
            )
        )

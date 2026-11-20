"""Keycloak provider against a live realm declared by the untracked ``.env``.

The realm issuer and audience reach FlextAuth through its production settings
boundary (``FLEXT_AUTH_AUTH__KEYCLOAK__*``); the token comes from the realm's
own token endpoint. The shared connectivity owner skips this module before any
fixture runs when the realm is not configured or not reachable.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from tests import FlextAuth, c, config, p, tm, u

pytestmark = [
    c.Tests.MARK.integration,
    c.Tests.MARK.connectivity(
        required_vars=c.Tests.KEYCLOAK_REQUIRED_VARS,
        url_var=c.Tests.KEYCLOAK_ISSUER_VAR,
    ),
    c.Tests.MARK.usefixtures("reset_auth_singleton"),
]


class TestsFlextAuthKeycloakLiveRealm:
    """Real realm tokens resolved and authorized through the composition root."""

    @staticmethod
    def authorizer() -> p.Auth.ScopedTokenAuthorizer:
        """Resolve the Keycloak provider the settings boundary composes.

        Returns:
            The Keycloak provider registered by ``FlextAuth()``.

        """
        provider = tm.ok(
            FlextAuth().fetch_provider(c.Auth.ProviderTypes.KEYCLOAK.value)
        )
        if not isinstance(provider, p.Auth.ScopedTokenAuthorizer):
            tm.reject()
        return provider

    @staticmethod
    def test_realm_token_is_authorized_for_its_granted_scope() -> None:
        """A real realm token grants the scope its groups or roles map to."""
        granted_scope = u.Cli.process_env()[c.Tests.KEYCLOAK_GRANTED_SCOPE_VAR]
        bearer = u.Tests.live_realm_bearer()
        granted = tm.ok(
            TestsFlextAuthKeycloakLiveRealm.authorizer().authorize(
                bearer, required_scope=granted_scope
            )
        )
        tm.that(granted, contains=granted_scope)

    @staticmethod
    def test_forged_superuser_group_is_rejected() -> None:
        """A real token re-encoded with the superuser group fails its signature."""
        policy = config.Auth.keycloak
        superuser_rule = next(
            rule for rule in policy.scope_rules if rule.scope == policy.superuser_scope
        )
        forged = u.Tests.forge_realm_claims(
            u.Tests.live_realm_bearer(), {"groups": [superuser_rule.groups[0]]}
        )
        tm.fail(
            TestsFlextAuthKeycloakLiveRealm.authorizer().authorize(
                forged, required_scope=policy.superuser_scope
            )
        )

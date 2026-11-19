"""Keycloak claim to canonical access-scope utilities.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import jwt
from flext_api import r, u

from flext_auth import c, config, m, p, t


class FlextAuthUtilitiesAuthScopes:
    """Verify Keycloak access tokens and derive and enforce canonical scopes."""

    @staticmethod
    def keycloak_signing_keys(issuer: str) -> t.Auth.SigningKeySource:
        """Build the cached signing-key source of one Keycloak realm.

        Args:
            issuer: Realm issuer URL.

        Returns:
            The realm signing-key source at ``config.Auth.keycloak.jwks_path``.

        """
        return jwt.PyJWKClient(f"{issuer.rstrip('/')}{config.Auth.keycloak.jwks_path}")

    @staticmethod
    def decode_keycloak_token(
        token: str,
        signing_keys: t.Auth.SigningKeySource,
        *,
        issuer: str,
        audience: str,
    ) -> p.Result[t.Auth.TokensClaimMap]:
        """Verify a Keycloak access token against its realm signing keys.

        The signature, ``exp``, ``iss`` and ``aud`` are all verified; only the
        configured realm algorithms are accepted.

        Args:
            token: Compact JWS access token.
            signing_keys: Signing-key source of the realm.
            issuer: Expected ``iss`` claim.
            audience: Expected ``aud`` claim.

        Returns:
            The verified claims, or the verification failure.

        """
        try:
            payload = jwt.decode(
                token,
                signing_keys.get_signing_key_from_jwt(token).key,
                algorithms=list(config.Auth.keycloak.algorithms),
                audience=audience,
                issuer=issuer,
                options={"require": ["exp", "iss", "aud"]},
            )
            claims = u.json_dict_adapter().validate_python(payload)
        except jwt.PyJWTError as exc:
            return r[t.Auth.TokensClaimMap].fail(f"Invalid token: {exc}", exception=exc)
        except c.ValidationError as exc:
            return r[t.Auth.TokensClaimMap].fail_op("Keycloak claim validation", exc)
        return r[t.Auth.TokensClaimMap].ok(claims)

    @staticmethod
    def keycloak_scopes(claims: t.Auth.TokensClaimMap) -> p.Result[frozenset[str]]:
        """Derive canonical scopes from Keycloak groups and realm roles.

        Each group or role name grants the scope of the first configured rule
        (``config.Auth.keycloak.scope_rules``) with a marker contained in the
        lower-cased name.

        Args:
            claims: Validated token claim mapping.

        Returns:
            The granted canonical scopes; failure when the claims violate the
            Keycloak claim contract.

        """
        try:
            parsed = m.Auth.KeycloakClaims.model_validate(claims)
        except c.ValidationError as exc:
            return r[frozenset[str]].fail_op("Keycloak claim validation", exc)
        rules = config.Auth.keycloak.scope_rules
        return r[frozenset[str]].ok(
            frozenset(
                scope
                for name in (*parsed.groups, *parsed.realm_access.roles)
                if (
                    scope := next(
                        (
                            rule.scope
                            for rule in rules
                            if any(marker in name.lower() for marker in rule.markers)
                        ),
                        None,
                    )
                )
                is not None
            )
        )

    @staticmethod
    def require_scope(
        granted: frozenset[str],
        required_scope: str | None = None,
    ) -> p.Result[frozenset[str]]:
        """Enforce one required scope; the configured superuser scope satisfies any.

        Args:
            granted: Canonical scopes granted to the caller.
            required_scope: Scope the operation requires; the configured
                ``default_required_scope`` when omitted.

        Returns:
            The granted scopes, or a failure naming the missing scope.

        """
        policy = config.Auth.keycloak
        required = required_scope or policy.default_required_scope
        if granted.isdisjoint({required, policy.superuser_scope}):
            return r[frozenset[str]].fail(f"missing required scope {required!r}")
        return r[frozenset[str]].ok(granted)


__all__: list[str] = ["FlextAuthUtilitiesAuthScopes"]

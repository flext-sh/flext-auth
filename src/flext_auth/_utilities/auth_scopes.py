"""Keycloak realm-token verification and canonical access-scope utilities.

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
    def bearer_token(authorization: str) -> p.Result[str]:
        """Extract the credential of a ``Bearer`` Authorization value.

        Args:
            authorization: ``Authorization`` header value.

        Returns:
            The bearer credential, or a failure for any other scheme.

        """
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != c.Auth.AuthorizationSchemes.BEARER.lower() or not token:
            return r[str].fail(c.Auth.KEYCLOAK_MISSING_BEARER)
        return r[str].ok(token)

    @staticmethod
    def keycloak_signing_keys(issuer: str) -> t.Auth.SigningKeySource:
        """Build the cached signing-key source of one Keycloak realm.

        Args:
            issuer: Normalized realm issuer URL.

        Returns:
            The realm signing-key source at ``config.Auth.keycloak.jwks_path``.

        """
        limits = config.Auth.keycloak.signing_keys
        return jwt.PyJWKClient(
            f"{issuer}{config.Auth.keycloak.jwks_path}",
            lifespan=limits.lifespan_seconds,
            timeout=limits.timeout_seconds,
            cooldown_duration=limits.cooldown_seconds,
        )

    @staticmethod
    def decode_keycloak_token(
        token: str,
        signing_keys: t.Auth.SigningKeySource,
        *,
        issuer: str,
        audience: str,
    ) -> p.Result[t.Auth.TokensClaimMap]:
        """Verify a Keycloak access token against its realm signing keys.

        The signature (with the key's own algorithm, restricted to the
        configured realm algorithms), ``exp``, ``iss``, ``aud`` and the
        access-token ``typ`` are all verified.

        Args:
            token: Compact JWS access token.
            signing_keys: Signing-key source of the realm.
            issuer: Expected ``iss`` claim.
            audience: Expected ``aud`` claim.

        Returns:
            The verified claims; a failure naming an unavailable key set, an
            invalid token, or a token that is not an access token.

        """
        policy = config.Auth.keycloak
        try:
            signing_key = signing_keys.get_signing_key_from_jwt(token)
        except jwt.PyJWKClientConnectionError as exc:
            return r[t.Auth.TokensClaimMap].fail(
                f"{c.Auth.KEYCLOAK_SIGNING_KEYS_UNAVAILABLE}: {exc}", exception=exc
            )
        except jwt.PyJWTError as exc:
            return r[t.Auth.TokensClaimMap].fail(
                f"{c.Auth.KEYCLOAK_REJECTED_CREDENTIAL}: {exc}", exception=exc
            )
        try:
            claims = u.json_dict_adapter().validate_python(
                jwt.decode(
                    token,
                    signing_key,
                    algorithms=list(policy.algorithms),
                    audience=audience,
                    issuer=issuer,
                    leeway=policy.leeway_seconds,
                    options={"require": ["exp", "iss", "aud"]},
                )
            )
        except jwt.PyJWTError as exc:
            return r[t.Auth.TokensClaimMap].fail(
                f"{c.Auth.KEYCLOAK_REJECTED_CREDENTIAL}: {exc}", exception=exc
            )
        except c.ValidationError as exc:
            return r[t.Auth.TokensClaimMap].fail_op("Keycloak claim validation", exc)
        if claims.get("typ") != policy.access_token_type:
            return r[t.Auth.TokensClaimMap].fail(c.Auth.KEYCLOAK_NOT_ACCESS_CREDENTIAL)
        return r[t.Auth.TokensClaimMap].ok(claims)

    @staticmethod
    def keycloak_scopes(claims: t.Auth.TokensClaimMap) -> p.Result[frozenset[str]]:
        """Derive canonical scopes from exact Keycloak group paths and realm roles.

        A rule of ``config.Auth.keycloak.scope_rules`` grants its scope when one
        of its group paths or realm roles is held exactly.

        Args:
            claims: Verified token claim mapping.

        Returns:
            The granted canonical scopes; failure when the claims violate the
            Keycloak claim contract.

        """
        try:
            parsed = m.Auth.KeycloakClaims.model_validate(claims)
        except c.ValidationError as exc:
            return r[frozenset[str]].fail_op("Keycloak claim validation", exc)
        groups = frozenset(parsed.groups)
        roles = frozenset(parsed.realm_access.roles)
        return r[frozenset[str]].ok(
            frozenset(
                rule.scope
                for rule in config.Auth.keycloak.scope_rules
                if not groups.isdisjoint(rule.groups)
                or not roles.isdisjoint(rule.roles)
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
            return r[frozenset[str]].fail(
                f"{c.Auth.KEYCLOAK_MISSING_SCOPE} {required!r}"
            )
        return r[frozenset[str]].ok(granted)


__all__: list[str] = ["FlextAuthUtilitiesAuthScopes"]

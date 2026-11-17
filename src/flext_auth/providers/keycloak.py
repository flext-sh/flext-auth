"""Keycloak OpenID Connect provider with claim-derived canonical scopes.

Validates Keycloak access tokens through the shared JWT owner and maps realm
groups and roles to the canonical ``read``/``write``/``admin`` scopes the
transports enforce. Claim parsing is defensive: only string entries count and
an absent or malformed claim yields no scope.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence, Sequence
from typing import override

from flext_auth import p, r, t
from flext_auth.providers import FlextAuthJwtTokenValidator, FlextAuthOidcProvider


class FlextAuthKeycloakProvider(FlextAuthOidcProvider):
    """Keycloak realm provider: OIDC validation plus canonical scope derivation."""

    @property
    @override
    def rfc_version(self) -> str:
        """RFC version this provider implements (OpenID Connect Core 1.0)."""
        return "OpenID Connect Core 1.0"

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            Set of supported methods (Keycloak, OIDC, validate and refresh).

        """
        return {"keycloak", "oidc", "validate", "refresh"}

    @override
    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate a Keycloak bearer token through the shared JWT owner.

        Args:
            token: Token string or token entity to validate.

        Returns:
            Whether the token passes signature and claim validation.

        """
        return self.claims(token).map(lambda _claims: True)

    def claims(self, token: str | p.Auth.Token) -> p.Result[t.Auth.TokensClaimMap]:
        """Return the validated Keycloak claims for a bearer token.

        Args:
            token: Token string or token entity to decode.

        Returns:
            The validated claim mapping, or a failure when validation rejects it.

        """
        return FlextAuthJwtTokenValidator(self).validate_token(
            self._extract_token_string(token)
        )

    def authorize(
        self,
        metadata: Mapping[str, str],
        *,
        required_scope: str = "read",
    ) -> p.Result[frozenset[str]]:
        """Validate the bearer credential and enforce one required scope.

        The transport supplies the invocation metadata; this owner decides,
        because it owns the token and scope semantics. ``admin`` satisfies any
        required scope.

        Args:
            metadata: Transport metadata carrying ``authorization``.
            required_scope: Canonical scope the operation requires.

        Returns:
            The granted scopes, or a failure for a missing/invalid credential or
            an insufficient scope.

        """
        scheme, _, token = metadata.get("authorization", "").partition(" ")
        if scheme.lower() != "bearer" or not token:
            return r[frozenset[str]].fail("missing bearer credential")
        claims = self.claims(token)
        if claims.failure:
            return r[frozenset[str]].fail(
                claims.error,
                exception=claims.exception,
            )
        scopes = self.scopes_from_claims(claims.value)
        if scopes.failure:
            return r[frozenset[str]].fail(
                scopes.error,
                exception=scopes.exception,
            )
        granted = scopes.value
        if required_scope not in granted and "admin" not in granted:
            return r[frozenset[str]].fail(f"missing required scope {required_scope!r}")
        return r[frozenset[str]].ok(granted)

    @staticmethod
    def scopes_from_claims(
        claims: t.Auth.TokensClaimMap,
    ) -> p.Result[frozenset[str]]:
        """Derive canonical access scopes from Keycloak groups and realm roles.

        Args:
            claims: Validated Keycloak claim mapping.

        Returns:
            The canonical scopes granted by the claim's group and role names.

        """
        granted = FlextAuthKeycloakProvider._claim_names(claims, "groups")
        granted |= FlextAuthKeycloakProvider._claim_names(
            claims,
            "realm_access",
            nested="roles",
        )
        scopes: set[str] = set()
        for name in granted:
            lowered = name.lower()
            if "admin" in lowered:
                scopes.add("admin")
            elif "editor" in lowered or "write" in lowered:
                scopes.add("write")
            elif "viewer" in lowered or "read" in lowered:
                scopes.add("read")
        return r[frozenset[str]].ok(frozenset(scopes))

    @staticmethod
    def _claim_names(
        claims: t.Auth.TokensClaimMap,
        key: str,
        *,
        nested: str | None = None,
    ) -> frozenset[str]:
        """Read one string sequence claim, optionally nested, without coercion.

        Returns:
            The string entries of the claim, empty when absent or malformed.

        """
        value: object = claims.get(key)
        if nested is not None:
            value = value.get(nested) if isinstance(value, Mapping) else None
        if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
            return frozenset()
        return frozenset(item for item in value if isinstance(item, str))


__all__: MutableSequence[str] = ["FlextAuthKeycloakProvider"]

"""Keycloak OpenID Connect provider with claim-derived canonical scopes.

Validates Keycloak access tokens through the shared JWT owner and grants the
canonical scopes that ``config.Auth.keycloak`` derives from realm groups and
roles.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import override

from flext_auth import c, p, r, t, u
from flext_auth.providers import FlextAuthJwtTokenValidator, FlextAuthOidcProvider


class FlextAuthKeycloakProvider(FlextAuthOidcProvider):
    """Keycloak realm provider: OIDC validation plus canonical scope derivation."""

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Returns:
            Set of supported methods (Keycloak, OIDC, validate and refresh).

        """
        return {c.Auth.ProviderTypes.KEYCLOAK.value, *super().supports()}

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
        """Return the validated claims of a Keycloak bearer token.

        Args:
            token: Token string or token entity to decode.

        Returns:
            The validated claim mapping, or the validation failure.

        """
        return FlextAuthJwtTokenValidator(self).validate_token(
            self._extract_token_string(token)
        )

    def authorize(
        self,
        authorization: str,
        *,
        required_scope: str | None = None,
    ) -> p.Result[frozenset[str]]:
        """Validate an ``Authorization`` header value and enforce one scope.

        Args:
            authorization: ``Bearer <token>`` header value from the transport.
            required_scope: Canonical scope the operation requires; the
                configured default when omitted.

        Returns:
            The granted scopes, or a failure for a missing or invalid bearer
            credential or an insufficient scope.

        """
        scheme, _, token = authorization.partition(" ")
        if scheme.lower() != c.Auth.AuthorizationSchemes.BEARER.lower() or not token:
            return r[frozenset[str]].fail("missing bearer credential")
        return (
            self
            .claims(token)
            .flat_map(u.Auth.keycloak_scopes)
            .flat_map(lambda granted: u.Auth.require_scope(granted, required_scope))
        )


__all__: MutableSequence[str] = ["FlextAuthKeycloakProvider"]

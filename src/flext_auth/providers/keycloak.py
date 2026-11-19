"""Keycloak OpenID Connect provider with claim-derived canonical scopes.

Verifies realm access tokens against the realm signing keys (signature,
``exp``, ``iss``, ``aud``) and grants the canonical scopes that
``config.Auth.keycloak`` derives from realm groups and roles.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableSequence
from typing import override

from flext_auth import c, m, p, t, u
from flext_auth.providers import FlextAuthOidcProvider


class FlextAuthKeycloakProvider(FlextAuthOidcProvider):
    """Keycloak realm provider: OIDC validation plus canonical scope derivation."""

    def __init__(self, settings: Mapping[str, t.Primitives] | None = None) -> None:
        """Bind the provider to one realm issuer and audience.

        Args:
            settings: Provider settings carrying ``issuer`` and ``audience``.

        Raises:
            ValueError: If the realm issuer or audience is missing.

        """
        super().__init__(settings)
        realm = m.Auth.ProviderConfig.model_validate({
            c.Auth.KEY_NAME: c.Auth.ProviderTypes.KEYCLOAK.value,
            "type": c.Auth.ProviderTypes.KEYCLOAK.value,
            **(settings or {}),
        })
        if not realm.issuer or not realm.audience:
            msg = "Keycloak provider requires the realm issuer and audience"
            raise ValueError(msg)
        self._issuer = realm.issuer
        self._audience = realm.audience
        self._signing_keys = u.Auth.keycloak_signing_keys(realm.issuer)

    @override
    def supports(self) -> set[str]:
        """Get supported authentication methods.

        Realm tokens are refreshed by the realm, never by this provider, so the
        inherited ``refresh`` capability is not advertised.

        Returns:
            Set of supported methods (Keycloak, OIDC and validate).

        """
        return {c.Auth.ProviderTypes.KEYCLOAK.value, *super().supports()} - {"refresh"}

    @override
    def validate(self, token: str | p.Auth.Token) -> p.Result[bool]:
        """Validate a Keycloak access token against the realm signing keys.

        Args:
            token: Token string or token entity to validate.

        Returns:
            Whether the token passes signature and claim validation.

        """
        return self.claims(token).map(lambda _claims: True)

    def claims(self, token: str | p.Auth.Token) -> p.Result[t.Auth.TokensClaimMap]:
        """Return the claims of a Keycloak access token verified by the realm keys.

        Args:
            token: Token string or token entity to decode.

        Returns:
            The validated claim mapping, or the validation failure.

        """
        return u.Auth.decode_keycloak_token(
            self._extract_token_string(token),
            self._signing_keys,
            issuer=self._issuer,
            audience=self._audience,
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
        return (
            u.Auth
            .bearer_token(authorization)
            .flat_map(self.claims)
            .flat_map(u.Auth.keycloak_scopes)
            .flat_map(lambda granted: u.Auth.require_scope(granted, required_scope))
        )


__all__: MutableSequence[str] = ["FlextAuthKeycloakProvider"]

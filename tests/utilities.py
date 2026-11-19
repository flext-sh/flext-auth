"""Test utilities for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import base64

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from flext_tests import u as flext_tests_u
from jwt.algorithms import RSAAlgorithm

from flext_auth import config, u as flext_auth_u
from tests import c, m, t


class TestsFlextAuthUtilities(flext_auth_u):
    """Test utilities for flext-auth — extends flext_auth.u and flext_u."""

    # Utilities namespace, not a test class: pytest must not collect the
    # ``Tests*``-named facade when test modules import it by its full name
    # (flext-ldap settings facade precedent).
    __test__: bool = False

    class Tests(flext_tests_u.Tests):
        """Test-specific utilities."""

        @staticmethod
        def realm_signing_key() -> t.Tests.RealmSigningKey:
            """Generate one RSA realm signing key.

            Returns:
                A fresh 2048-bit RSA private key.

            """
            return rsa.generate_private_key(public_exponent=65537, key_size=2048)

        @staticmethod
        def realm_key_set(signing_key: t.Tests.RealmSigningKey, key_id: str) -> str:
            """Publish the public half of a realm key as a JWKS document.

            Returns:
                The JSON key-set document served at the realm key-set path.

            """
            jwk = RSAAlgorithm.to_jwk(signing_key.public_key(), as_dict=True)
            return flext_auth_u.Cli.json_dumps({
                "keys": [
                    {
                        **jwk,
                        "kid": key_id,
                        "use": "sig",
                        "alg": config.Auth.keycloak.algorithms[0],
                    }
                ]
            }).unwrap()

        @staticmethod
        def live_realm_bearer() -> str:
            """Obtain a real access token from the configured live realm.

            Uses the password grant of the realm token endpoint with the test
            user that the untracked ``.env`` declares.

            Returns:
                The ``Authorization`` header value carrying the realm token.

            """
            env = flext_auth_u.Cli.process_env()
            issuer = env[c.Tests.KEYCLOAK_ISSUER_VAR].rstrip("/")
            with flext_auth_u.Api.HttpxClient(timeout=30) as client:
                response = client.post(
                    f"{issuer}{c.Tests.KEYCLOAK_GRANT_ENDPOINT_PATH}",
                    data={
                        "grant_type": "password",
                        "client_id": env[c.Tests.KEYCLOAK_CLIENT_ID_VAR],
                        "username": env[c.Tests.KEYCLOAK_USERNAME_VAR],
                        "password": env[c.Tests.KEYCLOAK_USER_CREDENTIAL_VAR],
                    },
                )
                response.raise_for_status()
            token = m.Tests.RealmTokenResponse.model_validate_json(response.content)
            return f"{c.Auth.AuthorizationSchemes.BEARER} {token.access_token}"

        @staticmethod
        def forge_realm_claims(bearer: str, claims: t.Auth.TokensClaimMap) -> str:
            """Rewrite a signed token's claims while keeping its original signature.

            Returns:
                The ``Authorization`` header value carrying the forged token.

            """
            scheme, _, token = bearer.partition(" ")
            header, payload, signature = token.split(".")
            original = flext_auth_u.json_dict_adapter().validate_json(
                base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4))
            )
            forged = flext_auth_u.Cli.json_dumps({**original, **claims}).unwrap()
            forged_payload = (
                base64.urlsafe_b64encode(forged.encode()).rstrip(b"=").decode()
            )
            return f"{scheme} {header}.{forged_payload}.{signature}"

        @staticmethod
        def sign_shared_secret_token(
            claims: t.Auth.TokensClaimMap, secret: str, key_id: str
        ) -> str:
            """Sign claims with HS256 under a realm key id (algorithm confusion).

            Returns:
                The compact JWS token signed with the shared secret.

            """
            return jwt.encode(
                dict(claims),
                secret,
                algorithm=c.Auth.Algorithms.HS256.value,
                headers={"kid": key_id},
            )

        @staticmethod
        def sign_realm_token(
            claims: t.Auth.TokensClaimMap,
            signing_key: t.Tests.RealmSigningKey,
            key_id: str,
        ) -> str:
            """Sign realm access-token claims with the realm algorithm.

            Returns:
                The compact JWS access token.

            """
            return jwt.encode(
                dict(claims),
                signing_key,
                algorithm=config.Auth.keycloak.algorithms[0],
                headers={"kid": key_id},
            )


# Published short name (ldap family shape): the tests package exposes the
# test-utilities facade as ``u`` so consumer modules import it as published
# instead of aliasing the class at every call site.
u = TestsFlextAuthUtilities

__all__: list[str] = ["TestsFlextAuthUtilities", "u"]

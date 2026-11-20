"""Real authentication composition fixtures.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar, override

import pytest

from flext_auth import FlextAuth, FlextAuthSettings, config
from flext_auth.providers import FlextAuthJwtProvider
from tests import c, p, t, u


class TestsFlextAuthFixtures:
    """Typed real API fixtures, without singleton resets or replacement adapters."""

    __test__: bool = False

    class PolicyLockedJwtProvider(FlextAuthJwtProvider):
        """Real JWT provider whose explicit domain policy rejects reconfiguration."""

        configuration_failure: ClassVar[p.Result[p.Auth.FlextAuthBaseProvider]]

        def __init__(
            self,
            configuration: t.ConfigurationMapping,
            failure: p.Result[p.Auth.FlextAuthBaseProvider],
        ) -> None:
            """Retain the policy failure and otherwise use real JWT behavior."""
            super().__init__(settings=configuration)
            TestsFlextAuthFixtures.PolicyLockedJwtProvider.configuration_failure = (
                failure
            )

        @override
        @staticmethod
        def with_configuration(
            configuration: t.ConfigurationMapping,
        ) -> p.Result[p.Auth.FlextAuthBaseProvider]:
            """Reject the requested lifecycle with the declared failure unchanged.

            Returns:
                The declared policy failure, with its original cause intact.

            """
            _ = configuration
            return TestsFlextAuthFixtures.PolicyLockedJwtProvider.configuration_failure

    @pytest.fixture
    def auth_api() -> p.Auth.Service:
        """Compose a fresh registry and real domain services for each test.

        Returns:
            A real auth API owning its registry and domain services.

        """
        return FlextAuth()

    class KeycloakRealm:
        """A real RS256 realm whose signing keys are served over HTTP."""

        audience: ClassVar[str] = "flext-test-client"
        key_id: ClassVar[str] = "flext-test-realm-key"

        def __init__(self, issuer: str, signing_key: t.Tests.RealmSigningKey) -> None:
            """Bind the realm issuer URL to its private signing key."""
            self.issuer = issuer
            self._signing_key = signing_key

        def settings(self) -> FlextAuthSettings:
            """Return Auth settings naming this realm's issuer and audience.

            Returns:
                Runtime settings that compose the Keycloak provider.

            """
            return FlextAuthSettings(
                Auth=FlextAuthSettings.AuthSettings(
                    Keycloak=FlextAuthSettings.AuthSettings.KeycloakSettings(
                        issuer=self.issuer,
                        audience=self.audience,
                    ),
                ),
            )

        def access_claims(
            self,
            claims: t.Auth.TokensClaimMap,
            *,
            lifetime_seconds: int = 300,
            omit: tuple[str, ...] = (),
        ) -> t.Auth.TokensClaimMap:
            """Build realm access-token claims the way Keycloak issues them.

            Returns:
                The issuer, audience, access ``typ`` and lifetime claims merged
                with ``claims``, without the ``omit`` names.

            """
            now = int(time.time())
            issued: t.Auth.TokensClaimMap = {
                "iss": self.issuer,
                "aud": self.audience,
                "typ": config.Auth.keycloak.access_token_type,
                "sub": "realm-user",
                "iat": now,
                "exp": now + lifetime_seconds,
                **claims,
            }
            return {name: value for name, value in issued.items() if name not in omit}

        def bearer(
            self,
            claims: t.Auth.TokensClaimMap,
            *,
            signing_key: t.Tests.RealmSigningKey | None = None,
            key_id: str | None = None,
            lifetime_seconds: int = 300,
            omit: tuple[str, ...] = (),
        ) -> str:
            """Sign realm access-token claims as a ``Bearer`` header value.

            Returns:
                The ``Authorization`` header value carrying the signed token.

            """
            token = u.Tests.sign_realm_token(
                self.access_claims(
                    claims, lifetime_seconds=lifetime_seconds, omit=omit
                ),
                signing_key or self._signing_key,
                key_id or self.key_id,
            )
            return f"{c.Auth.AuthorizationSchemes.BEARER} {token}"

    @pytest.fixture
    def unreachable_realm_issuer() -> str:
        """Return a loopback realm issuer whose port accepts no connection.

        Returns:
            An issuer URL on a port that was bound and released.

        """
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.bind(("127.0.0.1", 0))
            port = probe.getsockname()[1]
        return f"http://127.0.0.1:{port}/realms/unreachable"

    @pytest.fixture(scope="session")
    def foreign_realm_key() -> t.Tests.RealmSigningKey:
        """Return a signing key that the served realm does not publish.

        Returns:
            An RSA private key unknown to the realm.

        """
        return u.Tests.realm_signing_key()

    @pytest.fixture(scope="session")
    def keycloak_realm(
        request: pytest.FixtureRequest,
    ) -> TestsFlextAuthFixtures.KeycloakRealm:
        """Serve one immutable realm signing-key set over HTTP for the session.

        The server is shut down by the session finalizer this fixture registers.

        Returns:
            The realm issuing RS256 tokens verifiable through its served keys.

        """
        signing_key = u.Tests.realm_signing_key()
        key_set = u.Tests.realm_key_set(
            signing_key, TestsFlextAuthFixtures.KeycloakRealm.key_id
        ).encode()
        realm_path = "/realms/flext-test"
        key_set_path = f"{realm_path}{config.Auth.keycloak.jwks_path}"

        class KeySetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                found = self.path == key_set_path
                self.send_response(200 if found else 404)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(key_set if found else b"{}")

            @override
            def log_message(self, format: str, *args: t.Scalar) -> None:
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), KeySetHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop_server() -> None:
            server.shutdown()
            server.server_close()
            thread.join()

        request.addfinalizer(stop_server)
        host, port = server.server_address[:2]
        return TestsFlextAuthFixtures.KeycloakRealm(
            f"http://{host!s}:{port}{realm_path}",
            signing_key,
        )


__all__: list[str] = ["TestsFlextAuthFixtures"]

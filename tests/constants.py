"""Test constants for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_tests import c as flext_tests_c

from flext_auth import FlextAuthConstants


class TestsFlextAuthConstants(FlextAuthConstants):
    """Test constants for flext-auth — extends flext_auth.c."""

    TEST_CREDENTIAL: Final[str] = "TestPassword123!"

    class Tests(flext_tests_c.Tests):
        """Test-scoped constants (flext-tests facade composition)."""

        KEYCLOAK_ISSUER_VAR: Final[str] = "FLEXT_AUTH_AUTH__KEYCLOAK__ISSUER"
        KEYCLOAK_AUDIENCE_VAR: Final[str] = "FLEXT_AUTH_AUTH__KEYCLOAK__AUDIENCE"
        KEYCLOAK_CLIENT_ID_VAR: Final[str] = "FLEXT_AUTH_TEST_KEYCLOAK_CLIENT_ID"
        KEYCLOAK_USERNAME_VAR: Final[str] = "FLEXT_AUTH_TEST_KEYCLOAK_USERNAME"
        KEYCLOAK_USER_CREDENTIAL_VAR: Final[str] = "FLEXT_AUTH_TEST_KEYCLOAK_PASSWORD"
        KEYCLOAK_GRANTED_SCOPE_VAR: Final[str] = (
            "FLEXT_AUTH_TEST_KEYCLOAK_GRANTED_SCOPE"
        )
        KEYCLOAK_REQUIRED_VARS: Final[tuple[str, ...]] = (
            KEYCLOAK_ISSUER_VAR,
            KEYCLOAK_AUDIENCE_VAR,
            KEYCLOAK_CLIENT_ID_VAR,
            KEYCLOAK_USERNAME_VAR,
            KEYCLOAK_USER_CREDENTIAL_VAR,
            KEYCLOAK_GRANTED_SCOPE_VAR,
        )
        KEYCLOAK_GRANT_ENDPOINT_PATH: Final[str] = "/protocol/openid-connect/token"
        """Keycloak's documented realm token endpoint (external protocol)."""


c = TestsFlextAuthConstants

__all__: list[str] = ["TestsFlextAuthConstants", "c"]

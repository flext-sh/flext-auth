"""Test typings for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Literal

from flext_tests import t as flext_tests_t

from flext_auth import t as flext_auth_t


class TestsFlextAuthTypes(flext_auth_t):
    """Test typings for flext-auth — extends flext_auth.t."""

    class Tests(flext_tests_t.Tests):
        """Test-scoped literal aliases."""

        type TokenTypeLiteral = Literal["access", "refresh", "api", "bearer"]
        type ProviderTypeLiteral = Literal[
            "basic",
            "jwt",
            "oauth2",
            "saml",
            "ldap",
            "certificate",
            "kerberos",
            "apikey",
        ]


# Published short name (ldap family shape): the tests package exposes the
# test-typings facade as ``t`` so consumer modules import it as published
# instead of aliasing the class at every call site.
t = TestsFlextAuthTypes

__all__: list[str] = ["TestsFlextAuthTypes", "t"]

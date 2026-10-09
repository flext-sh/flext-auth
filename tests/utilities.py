"""Test utilities for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsUtilities

from flext_auth import FlextAuthUtilities


class TestsFlextAuthUtilities(FlextTestsUtilities, FlextAuthUtilities):
    """Test utilities for flext-auth — extends flext_auth.u and flext_tests.u."""

    # Utilities namespace, not a test class: pytest must not collect the
    # ``Tests*``-named facade when test modules import it by its full name
    # (flext-ldap settings facade precedent).
    __test__: bool = False

    class Tests(FlextTestsUtilities.Tests):
        """Test-specific utilities."""


# Published short name (ldap family shape): the tests package exposes the
# test-utilities facade as ``u`` so consumer modules import it as published
# instead of aliasing the class at every call site.
u = TestsFlextAuthUtilities

__all__: list[str] = ["TestsFlextAuthUtilities", "u"]

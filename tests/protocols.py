"""Test protocols for the flext-auth test suite.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import p as flext_tests_p

from flext_auth import p as flext_auth_p


class TestsFlextAuthProtocols(flext_auth_p):
    """Test protocols for flext-auth."""

    class Tests(flext_tests_p.Tests):
        """Test-specific protocols."""


p = TestsFlextAuthProtocols

__all__: list[str] = ["TestsFlextAuthProtocols", "p"]

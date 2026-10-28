"""Test protocols for the flext-auth test suite.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsProtocols

from flext_auth import FlextAuthProtocols


class TestsFlextAuthProtocols(FlextTestsProtocols, FlextAuthProtocols):
    """Test protocols for flext-auth."""

    class Tests(FlextTestsProtocols.Tests):
        """Test-specific protocols."""


p = TestsFlextAuthProtocols

__all__: list[str] = ["TestsFlextAuthProtocols", "p"]

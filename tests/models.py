"""Test models for the flext-auth test suite.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import m as flext_tests_m

from flext_auth import m as flext_auth_m


class TestsFlextAuthModels(flext_auth_m):
    """Test models for flext-auth."""

    class Tests(flext_tests_m.Tests):
        """Test-specific models."""


m = TestsFlextAuthModels

__all__: list[str] = ["TestsFlextAuthModels", "m"]

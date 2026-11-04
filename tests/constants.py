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


c = TestsFlextAuthConstants

__all__: list[str] = ["TestsFlextAuthConstants", "c"]

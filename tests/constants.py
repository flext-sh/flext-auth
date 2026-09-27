"""Test constants for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final

from flext_auth import FlextAuthConstants


class TestsFlextAuthConstants(FlextAuthConstants):
    """Test constants for flext-auth — extends flext_auth.c."""

    TEST_PASSWORD: Final[str] = "TestPassword123!"

    class _AuthConstants:
        """Auth-specific test constants."""

    class Tests(_AuthConstants):
        """Test-specific constants."""


c = TestsFlextAuthConstants

__all__: list[str] = ["TestsFlextAuthConstants", "c"]

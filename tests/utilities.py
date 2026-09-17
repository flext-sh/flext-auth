"""Test utilities for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuthUtilities
from flext_tests import FlextTestsUtilities


class TestsFlextAuthUtilities(FlextTestsUtilities, FlextAuthUtilities):
    """Test utilities for flext-auth — extends flext_auth.u and flext_tests.u."""
    
    class _AuthUtilities:
        """Auth-specific test utilities."""

    class TestsFlextAuth(TestsFlextAuthUtilities._AuthUtilities, FlextTestsUtilities.Tests):
        """Test-specific utilities."""
__all__: list[str] = ["TestsFlextAuthUtilities"]
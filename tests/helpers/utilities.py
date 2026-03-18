"""Test utilities extending flext_auth.utilities for test-specific functionality.

This module provides test-specific utility classes that extend the production
utilities from src/flext_auth/utilities.py. All test utilities use real
inheritance to expose the full hierarchy and avoid duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsUtilities

from flext_auth import FlextAuthUtilities


class TestsUtilities(FlextTestsUtilities, FlextAuthUtilities):
    """Test-specific utilities extending FlextAuthUtilities.

    Provides test-specific utility methods that extend production utilities
    with test-specific functionality. Uses real inheritance to expose
    the full hierarchy without duplication.
    """


u = TestsUtilities
__all__ = ["TestsUtilities", "u"]

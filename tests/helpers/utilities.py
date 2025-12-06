"""Test utilities extending flext_auth.utilities for test-specific functionality.

This module provides test-specific utility classes that extend the production
utilities from src/flext_auth/utilities.py. All test utilities use real
inheritance to expose the full hierarchy and avoid duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.utilities import FlextAuthUtilities


class TestsUtilities(FlextAuthUtilities):
    """Test-specific utilities extending FlextAuthUtilities.

    Provides test-specific utility methods that extend production utilities
    with test-specific functionality. Uses real inheritance to expose
    the full hierarchy without duplication.
    """

    # Test-specific utilities can be added here
    # All parent utilities are accessible via inheritance


# Standardized short name for use in tests (same pattern as flext-core)
u = TestsUtilities

__all__ = ["TestsUtilities", "u"]

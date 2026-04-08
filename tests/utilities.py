from __future__ import annotations

from flext_tests import FlextTestsUtilities

from flext_auth import FlextAuthUtilities


class TestsFlextAuthUtilities(FlextTestsUtilities, FlextAuthUtilities):
    """Test utilities for flext-auth."""

    class Tests(FlextTestsUtilities.Tests):
        """Test-specific utilities."""


u = TestsFlextAuthUtilities

__all__ = ["TestsFlextAuthUtilities", "u"]

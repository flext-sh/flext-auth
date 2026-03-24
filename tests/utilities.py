from __future__ import annotations

from flext_tests import FlextTestsUtilities

from flext_auth import FlextAuthUtilities


class FlextAuthTestUtilities(FlextTestsUtilities, FlextAuthUtilities):
    """Test utilities for flext-auth."""

    class Tests(FlextTestsUtilities.Tests):
        """Test-specific utilities."""


u = FlextAuthTestUtilities

__all__ = ["FlextAuthTestUtilities", "u"]

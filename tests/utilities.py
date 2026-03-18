from __future__ import annotations

from flext_tests.utilities import FlextTestsUtilities

from flext_auth import FlextAuthUtilities


class FlextAuthTestUtilities(FlextTestsUtilities, FlextAuthUtilities):
    """Test utilities for flext-auth."""

    class Tests:
        """Test-specific utilities."""


u = FlextAuthTestUtilities

__all__ = ["FlextAuthTestUtilities", "u"]

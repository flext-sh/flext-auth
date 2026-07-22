from __future__ import annotations

from flext_auth import FlextAuthUtilities
from flext_tests import FlextTestsUtilities


class TestsFlextAuthUtilities(FlextTestsUtilities, FlextAuthUtilities):
    """Test utilities for flext-auth."""

    class Tests(FlextTestsUtilities.Tests):
        """Test-specific utilities."""


u = TestsFlextAuthUtilities

__all__: list[str] = ["TestsFlextAuthUtilities", "u"]

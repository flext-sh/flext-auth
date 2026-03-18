from __future__ import annotations

from flext_tests.utilities import FlextTestsUtilities

from flext_auth import FlextAuthUtilities


class FlextAuthTestUtilities(FlextTestsUtilities, FlextAuthUtilities):
    class Tests:
        pass


u = FlextAuthTestUtilities

__all__ = ["FlextAuthTestUtilities", "u"]

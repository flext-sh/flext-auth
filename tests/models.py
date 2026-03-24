from __future__ import annotations

from flext_tests import FlextTestsModels

from flext_auth import FlextAuthModels


class FlextAuthTestModels(FlextTestsModels, FlextAuthModels):
    """Test models for flext-auth."""

    class Tests(FlextTestsModels.Tests):
        """Test-specific models."""


m = FlextAuthTestModels

__all__ = ["FlextAuthTestModels", "m"]

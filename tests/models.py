from __future__ import annotations

from flext_tests import FlextTestsModels

from flext_auth import FlextAuthModels


class TestsFlextAuthModels(FlextTestsModels, FlextAuthModels):
    """Test models for flext-auth."""

    class Tests(FlextTestsModels.Tests):
        """Test-specific models."""


m = TestsFlextAuthModels

__all__ = ["TestsFlextAuthModels", "m"]

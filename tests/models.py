from __future__ import annotations

from flext_tests.models import FlextTestsModels

from flext_auth import FlextAuthModels


class FlextAuthTestModels(FlextTestsModels, FlextAuthModels):
    """Test models for flext-auth."""

    class Tests:
        """Test-specific models."""


m = FlextAuthTestModels

__all__ = ["FlextAuthTestModels", "m"]

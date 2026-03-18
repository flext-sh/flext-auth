from __future__ import annotations

from flext_tests.typings import FlextTestsTypes

from flext_auth import FlextAuthTypes


class FlextAuthTestTypes(FlextTestsTypes, FlextAuthTypes):
    """Test types for flext-auth."""

    class Tests:
        """Test-specific types."""


t = FlextAuthTestTypes

__all__ = ["FlextAuthTestTypes", "t"]

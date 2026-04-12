from __future__ import annotations

from flext_tests import FlextTestsTypes

from flext_auth import FlextAuthTypes


class TestsFlextAuthTypes(FlextTestsTypes, FlextAuthTypes):
    """Test types for flext-auth."""

    class Tests(FlextTestsTypes.Tests):
        """Test-specific types."""


t = TestsFlextAuthTypes

__all__: list[str] = ["TestsFlextAuthTypes", "t"]

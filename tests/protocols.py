from __future__ import annotations

from flext_tests import FlextTestsProtocols

from flext_auth import FlextAuthProtocols


class TestsFlextAuthProtocols(FlextTestsProtocols, FlextAuthProtocols):
    """Test protocols for flext-auth."""

    class Tests(FlextTestsProtocols.Tests):
        """Test-specific protocols."""


p = TestsFlextAuthProtocols

__all__ = ["TestsFlextAuthProtocols", "p"]

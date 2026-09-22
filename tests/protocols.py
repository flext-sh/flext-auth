"""Test protocols for the flext-auth test suite."""

from __future__ import annotations

from flext_tests import FlextTestsProtocols

from flext_auth import p


class TestsFlextAuthProtocols(FlextTestsProtocols, p):
    """Test protocols for flext-auth."""

    class Tests(FlextTestsProtocols.Tests):
        """Test-specific protocols."""


p = TestsFlextAuthProtocols

__all__: list[str] = ["TestsFlextAuthProtocols", "p"]

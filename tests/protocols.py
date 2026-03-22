from __future__ import annotations

from flext_tests import FlextTestsProtocols

from flext_auth import FlextAuthProtocols


class FlextAuthTestProtocols(FlextTestsProtocols, FlextAuthProtocols):
    """Test protocols for flext-auth."""

    class Tests:
        """Test-specific protocols."""


p = FlextAuthTestProtocols

__all__ = ["FlextAuthTestProtocols", "p"]

from __future__ import annotations

from flext_tests.protocols import FlextTestsProtocols

from flext_auth import FlextAuthProtocols


class FlextAuthTestProtocols(FlextTestsProtocols, FlextAuthProtocols):
    class Tests:
        pass


p = FlextAuthTestProtocols

__all__ = ["FlextAuthTestProtocols", "p"]

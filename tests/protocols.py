"""Test protocol definitions for flext-auth.

Provides TestsFlextAuthProtocols, combining FlextTestsProtocols with
FlextAuthProtocols for test-specific protocol definitions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.protocols import FlextAuthProtocols
from flext_tests.protocols import FlextTestsProtocols


class TestsFlextAuthProtocols(FlextTestsProtocols, FlextAuthProtocols):
    """Test protocols combining FlextTestsProtocols and FlextAuthProtocols.

    Provides access to:
    - p.Tests.Docker.* (from FlextTestsProtocols)
    - p.Tests.Factory.* (from FlextTestsProtocols)
    - p.Auth.* (from FlextAuthProtocols)
    """

    pass


# Runtime aliases
p = TestsFlextAuthProtocols

__all__ = ["TestsFlextAuthProtocols", "p"]

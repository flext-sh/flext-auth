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
    - tp.Tests.Docker.* (from FlextTestsProtocols)
    - tp.Tests.Factory.* (from FlextTestsProtocols)
    - tp.Auth.* (from FlextAuthProtocols)
    """

    class Tests:
        """Project-specific test protocols.

        Extends FlextTestsProtocols.Tests with Auth-specific protocols.
        """

        class Auth:
            """Auth-specific test protocols."""


# Runtime aliases
p = TestsFlextAuthProtocols
tp = TestsFlextAuthProtocols

__all__ = ["TestsFlextAuthProtocols", "p", "tp"]

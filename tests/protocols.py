"""Test protocol definitions for flext-auth.

Provides TestsFlextAuthProtocols, combining p with
FlextAuthProtocols for test-specific protocol definitions.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import p

from flext_auth import FlextAuthProtocols


class TestsFlextAuthProtocols(p, FlextAuthProtocols):
    """Test protocols combining p and FlextAuthProtocols.

    Provides access to:
    - p.Tests.Docker.* (from p)
    - p.Tests.Factory.* (from p)
    - p.Auth.* (from FlextAuthProtocols)
    """


p = TestsFlextAuthProtocols
__all__ = ["TestsFlextAuthProtocols", "p"]

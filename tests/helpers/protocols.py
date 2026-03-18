"""Test protocols extending flext_auth.protocols for test-specific protocols.

This module provides test-specific protocol definitions that extend the
production protocols from src/flext_auth/protocols.py. All test protocols
use real inheritance to expose the full hierarchy and avoid duplication.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import FlextTestsProtocols

from flext_auth import FlextAuthProtocols


class TestsProtocols(FlextTestsProtocols, FlextAuthProtocols):
    """Test-specific protocols extending FlextAuthProtocols.

    Provides test-specific protocol definitions that extend production
    protocols with test-specific interfaces. Uses real inheritance to
    expose the full hierarchy without duplication.
    """


p = TestsProtocols
__all__ = ["TestsProtocols", "p"]

"""Test models for flext-auth.

Provides test-specific models extending m and FlextAuthModels
with proper hierarchy composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import m

from flext_auth import FlextAuthModels


class TestsFlextAuthModels(m, FlextAuthModels):
    """Test models - composition of m + FlextAuthModels.

    Hierarchy:
    - m: Generic test utilities from flext-tests
    - FlextAuthModels: Domain models from flext-auth
    - TestsFlextAuthModels: Composition + namespace .Tests

    Access patterns:
    - m.Tests.* - Project-specific test fixtures
    - m.AuthToken - Production domain models (inherited)
    - m.Tests.* - Generic test utilities
    """


# Short aliases for tests
tm = TestsFlextAuthModels
m = TestsFlextAuthModels

__all__ = ["TestsFlextAuthModels", "m", "tm"]

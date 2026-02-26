"""Test models for flext-auth.

Provides test-specific models extending FlextTestsModels and FlextAuthModels
with proper hierarchy composition.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.models import FlextAuthModels
from flext_tests.models import FlextTestsModels


class TestsFlextAuthModels(FlextTestsModels, FlextAuthModels):
    """Test models - composition of FlextTestsModels + FlextAuthModels.

    Hierarchy:
    - FlextTestsModels: Generic test utilities from flext-tests
    - FlextAuthModels: Domain models from flext-auth
    - TestsFlextAuthModels: Composition + namespace .Tests

    Access patterns:
    - m.Tests.* - Project-specific test fixtures
    - m.AuthToken - Production domain models (inherited)
    - FlextTestsModels.Tests.* - Generic test utilities
    """

    pass


# Short aliases for tests
tm = TestsFlextAuthModels
m = TestsFlextAuthModels

__all__ = ["TestsFlextAuthModels", "m", "tm"]

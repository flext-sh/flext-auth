"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import pytest

# Import FlextTestsDocker fixtures if available (optional dependency)
# Note: flext_tests is an optional test dependency - import may fail in some environments


@pytest.fixture
def mock_get_global():
    """Mock for FlextAuthSettings.get_global_instance.

    Returns:
        Mock object for global instance

    """

    # Use a simple object instead of MagicMock for better type safety
    class MockGlobal:
        def get_global_instance(self):
            return None

    return MockGlobal()

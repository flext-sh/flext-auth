"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

import pytest

# Import FlextTestsDocker fixtures if available (optional dependency)
# Note: flext_tests is an optional test dependency - import may fail in some environments


class MockGlobal:
    """Mock object for FlextAuthSettings.get_global_instance."""

    def get_global_instance(self) -> None:
        """Return None as mock global instance."""
        return


@pytest.fixture
def mock_get_global() -> MockGlobal:
    """Mock for FlextAuthSettings.get_global_instance."""
    return MockGlobal()

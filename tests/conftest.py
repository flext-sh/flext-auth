"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from unittest.mock import MagicMock

import pytest

# Import FlextTestsDocker fixtures if available
try:
    from flext_tests import FlextTestsDocker
except ImportError:
    # FlextTestsDocker not available, skip docker fixtures
    FlextTestsDocker = None


@pytest.fixture
def mock_get_global() -> MagicMock:
    """Mock for FlextAuthSettings.get_global_instance.

    Returns:
        MagicMock: Mock object for global instance

    """
    return MagicMock()

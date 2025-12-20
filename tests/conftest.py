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


# TODO: Implement proper singleton cleanup for FlextAuthSettings
# @pytest.fixture(autouse=True)
# def clear_auth_config_singleton() -> Generator[None]:
#     """Clear FlextAuthSettings singleton before each test to ensure clean state."""
#     # flext_auth.settings.FlextAuthSettings._reset_instance()
#     yield
#     # flext_auth.settings.FlextAuthSettings._reset_instance()


@pytest.fixture
def mock_get_global() -> MagicMock:
    """Mock for FlextAuthSettings.get_global_instance.

    Returns:
        MagicMock: Mock object for global instance

    """
    return MagicMock()

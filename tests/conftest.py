"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

import flext_auth.config

# Import and register FlextTestDocker fixtures if available
try:
    from flext_tests import FlextTestDocker

    # Register FlextTestDocker pytest fixtures in this module's namespace
    FlextTestDocker.register_pytest_fixtures(namespace=globals())
except ImportError:
    # FlextTestDocker not available, skip docker fixtures
    pass


@pytest.fixture(autouse=True)
def clear_auth_config_singleton() -> Generator[None]:
    """Clear FlextAuthConfig singleton before each test to ensure clean state."""
    flext_auth.config.FlextAuthConfig._reset_instance()
    yield
    flext_auth.config.FlextAuthConfig._reset_instance()


@pytest.fixture
def mock_get_global() -> MagicMock:
    """Mock for FlextAuthConfig.get_global_instance.

    Returns:
        MagicMock: Mock object for global instance

    """
    return MagicMock()

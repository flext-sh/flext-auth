"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from collections.abc import Generator
from unittest.mock import MagicMock

import pytest

import flext_auth.config


@pytest.fixture(autouse=True)
def clear_auth_config_singleton() -> Generator[None]:
    """Clear FlextAuthConfig singleton before each test to ensure clean state."""
    flext_auth.config.FlextAuthConfig.reset_global_instance()
    yield
    flext_auth.config.FlextAuthConfig.reset_global_instance()


@pytest.fixture
def mock_summary() -> MagicMock:
    """Mock for FlextAuthConfig.get_global_cli_summary.

    Returns:
        MagicMock: Mock object for CLI summary

    """
    return MagicMock()


@pytest.fixture
def mock_update() -> MagicMock:
    """Mock for FlextAuthConfig.update_global_from_cli.

    Returns:
        MagicMock: Mock object for CLI update

    """
    return MagicMock()


@pytest.fixture
def mock_get_global() -> MagicMock:
    """Mock for FlextAuthConfig.get_global_instance.

    Returns:
        MagicMock: Mock object for global instance

    """
    return MagicMock()

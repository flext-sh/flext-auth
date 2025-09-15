"""Test configuration for flext-auth."""

import sys
from collections.abc import Generator
from pathlib import Path
from unittest.mock import MagicMock

import pytest

import flext_auth.config

# Module setup
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))


@pytest.fixture(autouse=True)
def clear_auth_config_singleton() -> Generator[None]:
    """Clear FlextAuthConfig singleton before each test to ensure clean state."""
    flext_auth.config.FlextAuthConfig.clear_global_instance()
    yield
    flext_auth.config.FlextAuthConfig.clear_global_instance()


@pytest.fixture
def mock_summary() -> MagicMock:
    """Mock for FlextAuthConfig.get_global_cli_summary."""
    return MagicMock()


@pytest.fixture
def mock_update() -> MagicMock:
    """Mock for FlextAuthConfig.update_global_from_cli."""
    return MagicMock()


@pytest.fixture
def mock_get_global() -> MagicMock:
    """Mock for FlextAuthConfig.get_global_instance."""
    return MagicMock()

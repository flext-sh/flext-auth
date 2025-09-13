"""Test configuration for flext-auth."""

import sys
from collections.abc import Generator
from pathlib import Path

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

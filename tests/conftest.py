"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from flext_auth import FlextAuth, FlextAuthSettings

# Import FlextTestsDocker fixtures if available (optional dependency)
# Note: flext_tests is an optional test dependency - import may fail in some environments


@pytest.fixture(autouse=True)
def _reset_singletons() -> Iterator[None]:
    """Reset FlextAuth and FlextAuthSettings singletons between tests.

    This prevents singleton corruption from leaking between tests.
    FlextAuthSettings uses __new__ singleton pattern that caches instances
    and __init__ uses object.__setattr__ for updates, bypassing Pydantic
    coercion. Without reset, a test passing auth_secret as str corrupts
    all subsequent tests.
    """
    yield
    # Teardown: reset singletons after each test
    FlextAuthSettings._reset_instance()
    FlextAuth._instance = None


@pytest.fixture
def mock_get_global() -> object:
    """Mock for FlextAuthSettings.get_global_instance.

    Returns:
        Mock object for global instance

    """

    # Use a simple object instead of MagicMock for better type safety
    class MockGlobal:
        def get_global_instance(self) -> None:
            return None

    return MockGlobal()

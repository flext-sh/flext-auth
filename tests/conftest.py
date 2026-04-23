"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    Iterator,
)

import pytest

from flext_auth import FlextAuth, FlextAuthSettings


class _MockGlobal:
    """Mock for FlextAuthSettings.get_global."""

    def get_global(self) -> None:
        """Return None as mock global instance."""
        return


@pytest.fixture(autouse=True)
def reset_auth_singleton() -> Iterator[None]:
    """Reset FlextAuth singleton between tests.

    The centralized plugin handles FlextSettings/FlextContainer reset.
    This fixture additionally resets the FlextAuth service singleton
    which is project-specific state not covered by the plugin.
    """
    yield
    FlextAuth._instance = None


@pytest.fixture
def auth_settings() -> FlextAuthSettings:
    """Provide clean FlextAuthSettings for auth tests."""
    return FlextAuthSettings(debug=True)


@pytest.fixture
def mock_get_global() -> _MockGlobal:
    """Mock for FlextAuthSettings.get_global.

    Returns:
        Mock t.JsonValue for global instance

    """
    return _MockGlobal()

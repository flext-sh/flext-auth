"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from flext_auth import FlextAuth, FlextAuthSettings


class _MockGlobal:
    """Mock for FlextAuthSettings.get_global."""

    def get_global(self) -> None:
        """Return None as mock global instance."""
        return None


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
    FlextAuthSettings._reset_instance()
    FlextAuth._instance = None


@pytest.fixture
def mock_get_global() -> _MockGlobal:
    """Mock for FlextAuthSettings.get_global.

    Returns:
        Mock t.NormalizedValue for global instance

    """
    return _MockGlobal()

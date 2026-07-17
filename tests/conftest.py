"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

import pytest

from flext_auth import FlextAuth

if TYPE_CHECKING:
    from collections.abc import Iterator


@pytest.fixture
def reset_auth_singleton(reset_settings: None) -> Iterator[None]:
    """Reset FlextAuth singleton and shared settings between tests."""
    _ = reset_settings
    FlextAuth.reset_for_testing()
    yield
    FlextAuth.reset_for_testing()

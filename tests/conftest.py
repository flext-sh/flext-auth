"""Test configuration for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from flext_auth import FlextAuth


@pytest.fixture(autouse=True)
def reset_auth_singleton() -> Iterator[None]:
    """Reset FlextAuth singleton between tests."""
    yield
    FlextAuth._instance = None

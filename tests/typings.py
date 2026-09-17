"""Test typings for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import t


class _AuthTypes:
    """Auth-specific test types."""


class TestsFlextAuthTypes(t):
    """Test typings for flext-auth — extends flext_auth.t."""

    class TestsFlextAuth(_AuthTypes):
        """Test-specific types."""


__all__: list[str] = ["TestsFlextAuthTypes"]

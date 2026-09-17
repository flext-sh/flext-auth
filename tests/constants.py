"""Test constants for flext-auth.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import c


class TestsFlextAuthConstants(c):
    """Test constants for flext-auth — extends flext_auth.c."""
    
    class _AuthConstants:
        """Auth-specific test constants."""

    class TestsFlextAuth(TestsFlextAuthConstants._AuthConstants):
        """Test-specific constants."""
__all__: list[str] = ["TestsFlextAuthConstants"]
"""Test models for the flext-auth test suite.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from flext_tests import FlextTestsModels

from flext_auth import FlextAuthModels


class TestsFlextAuthModels(FlextTestsModels, FlextAuthModels):
    """Test models for flext-auth."""

    class Tests(FlextTestsModels.Tests):
        """Test-specific models."""


m = TestsFlextAuthModels

__all__: list[str] = ["TestsFlextAuthModels", "m"]

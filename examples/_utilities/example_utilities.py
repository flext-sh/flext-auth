"""Example utilities for FLEXT Auth examples.

This module provides common utilities used across all example files.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import (
        Callable,
    )

    from flext_auth import t


class FlextAuthExampleUtilities:
    """Shared owner for example utility helpers."""

    @staticmethod
    def basic_example_runner(
        sync_examples: t.SequenceOf[Callable[[], None]],
        examples: t.SequenceOf[Callable[[], None]],
    ) -> None:
        """Run all examples using the shared runner (DRY principle)."""
        for example in sync_examples:
            example()

        for example in examples:
            example()

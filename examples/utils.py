"""Example utilities for FLEXT Auth examples.

This module provides common utilities used across all example files.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import (
    Callable,
    Sequence,
)


def basic_example_runner(
    sync_examples: Sequence[Callable[[], None]],
    examples: Sequence[Callable[[], None]],
) -> None:
    """Run all examples using the shared runner (DRY principle)."""
    for example in sync_examples:
        example()

    for example in examples:
        example()

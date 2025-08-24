#!/usr/bin/env python3
"""Example utilities for FLEXT Auth examples.

This module provides common utilities used across all example files.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable


def basic_example_runner(
    sync_examples: list[Callable[[], None]],
    async_examples: list[Callable[[], Awaitable[None]]],
) -> None:
    """Run all examples using the shared runner (DRY principle)."""
    # Run sync examples
    for example in sync_examples:
        with contextlib.suppress(Exception):
            example()

    # Run async examples
    async def run_async_examples() -> None:
        for example in async_examples:
            with contextlib.suppress(Exception):
                await example()

    # Run async examples in event loop
    asyncio.run(run_async_examples())

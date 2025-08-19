#!/usr/bin/env python3
"""Example utilities for FLEXT Auth examples.

This module provides common utilities used across all example files.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable


def basic_example_runner(
    sync_examples: list[Callable[[], None]],
    async_examples: list[Callable[[], Awaitable[None]]],
) -> None:
    """Run all examples using the shared runner (DRY principle)."""
    print("🚀 Running FLEXT Auth Examples")
    print("=" * 50)

    # Run sync examples
    for example in sync_examples:
        try:
            print(f"📝 Running: {example.__name__}")
            example()
            print(f"✅ {example.__name__} completed successfully")
        except Exception as e:
            print(f"❌ {example.__name__} failed: {e}")
        print("-" * 30)

    # Run async examples
    async def run_async_examples() -> None:
        for example in async_examples:
            try:
                print(f"📝 Running: {example.__name__}")
                await example()
                print(f"✅ {example.__name__} completed successfully")
            except Exception as e:
                print(f"❌ {example.__name__} failed: {e}")
            print("-" * 30)

    # Run async examples in event loop
    asyncio.run(run_async_examples())

    print("🎉 All examples completed!")

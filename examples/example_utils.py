"""Shared utilities for FLEXT Auth examples.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import TypeVar

T = TypeVar("T")


def run_example_suite(
    title: str,
    sync_examples: list[Callable[[], None]],
    async_examples: list[Callable[[], Awaitable[None]]] | None = None,
    success_message: str | None = None,
) -> None:
    """Run a complete example suite with standardized error handling.

    Args:
      title: Title to display for the example suite
      sync_examples: List of synchronous example functions to run
      async_examples: List of asynchronous example functions to run
      success_message: Custom success message (optional)

    """

    async def _run_suite() -> None:
        # Print header with dynamic width based on title
        max(50, len(title) + 10)

        # Run synchronous examples
        for example_func in sync_examples:
            example_func()

        # Run asynchronous examples if provided
        if async_examples:
            for async_example_func in async_examples:
                await async_example_func()

        # Print success message
        if success_message:
            pass

    # Run the async suite
    asyncio.run(_run_suite())


def create_example_runner(
    title: str,
    success_message: str | None = None,
) -> Callable[
    [list[Callable[[], None]], list[Callable[[], Awaitable[None]]] | None],
    None,
]:
    """Create a reusable example runner function.

    This factory function implements the Factory pattern to create
    standardized example runners, reducing boilerplate code.

    Args:
      title: Title for the example suite
      success_message: Custom success message

    Returns:
      Function that runs example suite with given parameters

    """

    def runner(
        sync_examples: list[Callable[[], None]],
        async_examples: list[Callable[[], Awaitable[None]]] | None = None,
    ) -> None:
        """Run example suite with predefined title and message."""
        run_example_suite(title, sync_examples, async_examples, success_message)

    return runner


# Pre-configured runners for common use cases
basic_example_runner = create_example_runner(
    "FLEXT Auth - Basic Usage Examples",
    (
        "ALL BASIC EXAMPLES COMPLETED SUCCESSFULLY!\n"
        "All methods used exist and work correctly."
    ),
)

advanced_example_runner = create_example_runner(
    "FLEXT Auth - Advanced Features Examples",
    (
        "ALL ADVANCED EXAMPLES COMPLETED SUCCESSFULLY!\n"
        "All methods demonstrate real flext-auth advanced functionality."
    ),
)

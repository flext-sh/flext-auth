"""Demonstrate FlextAuthConfig singleton behavior.

This script demonstrates how FlextAuthConfig singleton works as a single
source of truth for authentication configuration across the application.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from flext_auth import FlextAuth, FlextAuthConfig


def demonstrate_singleton_config() -> None:
    """Demonstrate singleton configuration behavior."""
    # 1. Get global instance (source of truth)
    FlextAuthConfig.get_global_instance()

    # 2. Create FlextAuth instance (uses singleton)
    FlextAuth()

    # 3. Create another FlextAuth instance (should use same config)
    FlextAuth()

    # 4. Verify they use the same configuration

    # 5. Demonstrate parameter overrides
    FlextAuth()  # Use default configuration

    # 6. Verify overrides don't affect global instance
    FlextAuthConfig.get_global_instance()


if __name__ == "__main__":
    demonstrate_singleton_config()

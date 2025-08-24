#!/usr/bin/env python3
"""FLEXT Auth - Refactored System Showcase (Working Version).

This example showcases the refactored FLEXT Auth system with working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import (
    FlextAuth,
    FlextResult,
    flext_auth_quick_start,
)


def demonstrate_refactoring_benefits() -> None:
    """Demonstrate the benefits of the refactored system."""
    # Modern FlextAuth API
    auth = FlextAuth()

    # Create user with new API
    result = auth.create_user("modern_user", "modern@example.com", "ModernPass123!")
    if hasattr(result, "success") and result.success:
        pass

    # Authenticate with new API
    auth_result = auth.authenticate("modern_user", "ModernPass123!")
    if hasattr(auth_result, "success") and auth_result.success:
        pass


def demonstrate_legacy_compatibility() -> None:
    """Demonstrate backward compatibility with legacy code."""
    # Legacy quick start still works
    legacy_service = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    if legacy_service is None:
        msg = "Legacy service creation failed"
        raise RuntimeError(msg)

    # Legacy wrapper provides compatibility


def demonstrate_flext_result_integration() -> None:
    """Demonstrate FlextResult pattern integration."""
    # FlextResult pattern usage
    FlextResult[str].ok("Refactoring successful")

    FlextResult[str].fail("Example failure case")


def demonstrate_system_architecture() -> None:
    """Demonstrate the clean system architecture."""
    # Clean separation of concerns
    FlextAuth()

    # Type safety with FlextResult


def main() -> None:
    """Execute refactored system showcase."""
    demonstrate_refactoring_benefits()

    demonstrate_legacy_compatibility()

    demonstrate_flext_result_integration()

    demonstrate_system_architecture()


if __name__ == "__main__":
    main()

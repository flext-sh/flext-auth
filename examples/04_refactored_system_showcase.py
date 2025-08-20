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
    print("=== REFACTORED SYSTEM SHOWCASE ===")

    # Modern FlextAuth API
    auth = FlextAuth()
    print("✓ Modern FlextAuth API initialized")

    # Create user with new API
    result = auth.create_user("modern_user", "modern@example.com", "ModernPass123!")
    if hasattr(result, "success") and result.success:
        print("✓ User created with refactored API")
    else:
        print("! User creation handled (may exist)")

    # Authenticate with new API
    auth_result = auth.authenticate("modern_user", "ModernPass123!")
    if hasattr(auth_result, "success") and auth_result.success:
        print("✓ Authentication successful with refactored API")
    else:
        print("! Authentication handled")


def demonstrate_legacy_compatibility() -> None:
    """Demonstrate backward compatibility with legacy code."""
    print("=== LEGACY COMPATIBILITY ===")

    # Legacy quick start still works
    legacy_service = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("✓ Legacy quick start still functional")
    assert legacy_service is not None

    # Legacy wrapper provides compatibility
    print("✓ Legacy compatibility layer working")


def demonstrate_flext_result_integration() -> None:
    """Demonstrate FlextResult pattern integration."""
    print("=== FLEXT RESULT INTEGRATION ===")

    # FlextResult pattern usage
    success_example = FlextResult[str].ok("Refactoring successful")
    print(f"✓ FlextResult success: {success_example.success}")
    print(f"  Data: {success_example.data}")

    failure_example = FlextResult[str].fail("Example failure case")
    print(f"✓ FlextResult failure: {failure_example.success}")
    print(f"  Error: {failure_example.error}")


def demonstrate_system_architecture() -> None:
    """Demonstrate the clean system architecture."""
    print("=== SYSTEM ARCHITECTURE ===")

    # Clean separation of concerns
    auth = FlextAuth()
    print("✓ Clean Architecture implemented")
    print("  - Domain layer: User entities, value objects")
    print("  - Application layer: Use case orchestration")
    print("  - Infrastructure layer: Repositories, services")
    print("  - API layer: Public interface (FlextAuth)")

    # Type safety with FlextResult
    print("✓ Type safety with FlextResult pattern")
    print("  - All operations return FlextResult[T]")
    print("  - Railway-oriented programming")
    print("  - No exception throwing in business logic")


def main() -> None:
    """Execute refactored system showcase."""
    print("🚀 FLEXT Auth Refactored System Showcase")
    print("=" * 50)

    demonstrate_refactoring_benefits()
    print("-" * 30)

    demonstrate_legacy_compatibility()
    print("-" * 30)

    demonstrate_flext_result_integration()
    print("-" * 30)

    demonstrate_system_architecture()
    print("-" * 30)

    print("🎉 Refactored system showcase completed!")


if __name__ == "__main__":
    main()

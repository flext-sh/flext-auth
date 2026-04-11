"""FLEXT Auth - Refactored System Showcase (Working Version).

This example showcases the refactored FLEXT Auth system with working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthQuickstart, FlextAuthSettings
from flext_core import r


def demonstrate_refactoring_benefits() -> None:
    """Demonstrate the benefits of the refactored system."""
    auth: FlextAuth = FlextAuth()
    auth.register_user("modern_user", "modern@example.com", "ModernPass123!")
    auth_result = auth.authenticate_user("modern_user", "ModernPass123!")
    if auth_result.success:
        auth_data = auth_result.value
        user_name = auth_data.name
        print(f"Authenticated user: {user_name}")


def demonstrate_quickstart_functionality() -> None:
    """Demonstrate FlextAuthQuickstart convenience functionality."""
    quickstart: FlextAuthQuickstart = FlextAuthQuickstart()
    quickstart_result = quickstart.flext_auth_quick_start(create_admin_user=False)
    if quickstart_result.success:
        admin_credentials = quickstart_result.value
        print(f"Admin credentials created: {admin_credentials}")
    auth_service = FlextAuth()
    auth_service.register_user(
        "quickstart_user",
        "quickstart@example.com",
        "QuickstartPassword123!",
    )


def demonstrate_flext_result_integration() -> None:
    """Demonstrate r pattern integration."""
    _ = r[str].ok("Refactoring successful")
    _ = r[str].fail("Example failure case")
    auth: FlextAuth = FlextAuth()
    auth.authenticate_user("test_user", "password")


def demonstrate_system_architecture() -> None:
    """Demonstrate the clean system architecture."""
    _ = FlextAuth()
    _ = FlextAuthSettings()


def demonstrate_error_handling() -> None:
    """Demonstrate proper error handling patterns."""
    auth: FlextAuth = FlextAuth()
    auth.register_user("weakuser", "weak@example.com", "123")
    auth.authenticate_user("nonexistent", "password")


def main() -> None:
    """Execute refactored system showcase."""
    demonstrate_refactoring_benefits()
    demonstrate_quickstart_functionality()
    demonstrate_flext_result_integration()
    demonstrate_system_architecture()
    demonstrate_error_handling()


if __name__ == "__main__":
    main()

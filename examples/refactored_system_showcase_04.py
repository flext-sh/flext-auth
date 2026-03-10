"""FLEXT Auth - Refactored System Showcase (Working Version).

This example showcases the refactored FLEXT Auth system with working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_core import FlextResult

from flext_auth import FlextAuth, FlextAuthQuickstart, FlextAuthSettings


def demonstrate_refactoring_benefits() -> None:
    """Demonstrate the benefits of the refactored system."""
    auth: FlextAuth = FlextAuth()
    result = auth.register_user("modern_user", "modern@example.com", "ModernPass123!")
    if result.is_success:
        pass
    auth_result = auth.authenticate_user("modern_user", "ModernPass123!")
    if auth_result.is_success:
        auth_data = auth_result.value
        user_name = auth_data.name
        print(f"Authenticated user: {user_name}")


def demonstrate_quickstart_functionality() -> None:
    """Demonstrate FlextAuthQuickstart convenience functionality."""
    quickstart: FlextAuthQuickstart = FlextAuthQuickstart()
    quickstart_result = quickstart.flext_auth_quick_start(create_admin_user=False)
    if quickstart_result.is_success:
        admin_credentials = quickstart_result.value
        print(f"Admin credentials created: {admin_credentials}")
    auth_service = FlextAuth()
    reg_result = auth_service.register_user(
        "quickstart_user", "quickstart@example.com", "QuickstartPassword123!"
    )
    if reg_result.is_success:
        pass


def demonstrate_flext_result_integration() -> None:
    """Demonstrate FlextResult pattern integration."""
    _ = FlextResult[str].ok("Refactoring successful")
    _ = FlextResult[str].fail("Example failure case")
    auth: FlextAuth = FlextAuth()
    auth_result = auth.authenticate_user("test_user", "password")
    if auth_result.is_success:
        pass


def demonstrate_system_architecture() -> None:
    """Demonstrate the clean system architecture."""
    _ = FlextAuth()
    _ = FlextAuthSettings()


def demonstrate_error_handling() -> None:
    """Demonstrate proper error handling patterns."""
    auth: FlextAuth = FlextAuth()
    weak_result = auth.register_user("weakuser", "weak@example.com", "123")
    if weak_result.is_failure:
        pass
    nonexistent_result = auth.authenticate_user("nonexistent", "password")
    if nonexistent_result.is_failure:
        pass


def main() -> None:
    """Execute refactored system showcase."""
    demonstrate_refactoring_benefits()
    demonstrate_quickstart_functionality()
    demonstrate_flext_result_integration()
    demonstrate_system_architecture()
    demonstrate_error_handling()


if __name__ == "__main__":
    main()

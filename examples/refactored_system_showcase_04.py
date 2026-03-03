#!/usr/bin/env python3
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
    # Modern FlextAuth API
    auth: FlextAuth = FlextAuth()

    # Create user with proper API (register_user not create_user)
    result = auth.register_user("modern_user", "modern@example.com", "ModernPass123!")
    if result.is_success:
        pass

    # Authenticate with proper API
    auth_result = auth.authenticate_user("modern_user", "ModernPass123!")
    if auth_result.is_success:
        auth_data = auth_result.value
        # auth_data is Identity object, access name field directly
        user_name = auth_data.name
        print(f"Authenticated user: {user_name}")


def demonstrate_quickstart_functionality() -> None:
    """Demonstrate FlextAuthQuickstart convenience functionality."""
    # Quickstart utility for rapid setup
    quickstart: FlextAuthQuickstart = FlextAuthQuickstart()
    # flext_auth_quick_start returns r[list[str]]
    quickstart_result = quickstart.flext_auth_quick_start(create_admin_user=False)
    if quickstart_result.is_success:
        admin_credentials = quickstart_result.value
        print(f"Admin credentials created: {admin_credentials}")

    # Create a separate FlextAuth instance for the demo
    auth_service = FlextAuth()

    # Standard user registration
    reg_result = auth_service.register_user(
        "quickstart_user",
        "quickstart@example.com",
        "QuickstartPassword123!",
    )

    if reg_result.is_success:
        pass


def demonstrate_flext_result_integration() -> None:
    """Demonstrate FlextResult pattern integration."""
    # FlextResult pattern usage
    _ = FlextResult[str].ok("Refactoring successful")

    _ = FlextResult[str].fail("Example failure case")

    # Show real usage in auth operations - using authenticate instead
    auth: FlextAuth = FlextAuth()
    # FlextAuth doesn't have generate_token_for_user method directly
    # This would be done through a provider or service
    auth_result = auth.authenticate_user("test_user", "password")

    if auth_result.is_success:
        pass


def demonstrate_system_architecture() -> None:
    """Demonstrate the clean system architecture."""
    # Clean separation of concerns
    _ = FlextAuth()

    # Note: FlextAuth doesn't have a get_config() method
    # Configuration is passed during initialization
    _ = FlextAuthSettings()


def demonstrate_error_handling() -> None:
    """Demonstrate proper error handling patterns."""
    auth: FlextAuth = FlextAuth()

    # Try to register user with weak password
    weak_result = auth.register_user("weakuser", "weak@example.com", "123")
    if weak_result.is_failure:
        pass

    # Try to authenticate non-existent user
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

#!/usr/bin/env python3
"""FLEXT Auth - Refactored System Showcase (Working Version).

This example showcases the refactored FLEXT Auth system with working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthQuickstart
from flext_core import FlextResult


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
        user_data = auth_data.get("user", {})
        user_data.get("username", "Unknown") if isinstance(user_data, dict) else "User"


def demonstrate_legacy_compatibility() -> None:
    """Demonstrate backward compatibility with legacy code."""
    # Legacy quick start still works
    quickstart = FlextAuthQuickstart()
    legacy_service: FlextAuth = quickstart.flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    # Show it works the same way
    reg_result = legacy_service.register_user(
        "legacy_user",
        "legacy@example.com",
        "LegacyPassword123!",
    )

    if reg_result.is_success:
        pass


def demonstrate_flext_result_integration() -> None:
    """Demonstrate FlextResult pattern integration."""
    # FlextResult pattern usage
    FlextResult[str].ok("Refactoring successful")

    FlextResult[str].fail("Example failure case")

    # Show real usage in auth operations
    auth: FlextAuth = FlextAuth()
    token_result = auth.generate_jwt_token("test_user_id")

    if token_result.is_success:
        pass


def demonstrate_system_architecture() -> None:
    """Demonstrate the clean system architecture."""
    # Clean separation of concerns
    FlextAuth()

    # Note: FlextAuth doesn't have a get_config() method
    # Configuration is passed during initialization
    from flext_auth import FlextAuthConfig

    FlextAuthConfig()


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
    demonstrate_legacy_compatibility()
    demonstrate_flext_result_integration()
    demonstrate_system_architecture()
    demonstrate_error_handling()


if __name__ == "__main__":
    main()

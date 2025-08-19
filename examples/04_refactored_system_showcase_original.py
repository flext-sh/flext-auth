#!/usr/bin/env python3
"""Advanced example showcasing the refactored FlextAuth system.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import traceback
from pathlib import Path

from flext_core import FlextContainer

from flext_auth import (
    FlextAuth,
    FlextUser,
    FlextUserEmail,
    FlextUsername,
    FlextUserRole,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_email,
)


def demonstrate_refactoring_benefits() -> None:
    """Demonstrate the benefits of the refactored architecture."""
    # BEFORE: Would need 50+ lines of manual setup
    # AFTER: 3 lines with anti-boilerplate patterns

    # Using top-level import

    # One-line complete authentication system
    result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    if result.success:
        pass

    # Using top-level import

    # Constructor now properly injects all dependencies
    FlextAuth()


def demonstrate_modular_architecture() -> None:
    """Demonstrate the modular architecture following SOLID principles."""
    # Import from specialized modules (Single Responsibility Principle)
    # Using top-level imports

    # Test helper functions
    flext_auth_validate_email("user@example.com")
    flext_auth_validate_email("invalid-email")
    # Note: flext_auth_validate_username is not available in current API
    password_hash = flext_auth_hash_password("TestPassword123!")

    # Handle password hash result (may be wrapper object)
    if hasattr(password_hash, "value"):
        pass
    else:
        str(password_hash)

    # Test decorator availability

    # Test mixin availability


def demonstrate_clean_architecture() -> None:
    """Demonstrate Clean Architecture implementation."""
    # Domain layer - Pure business logic (using top-level imports)

    # Create domain entities
    FlextUser(
        id="user-123",
        username="domainuser",
        email="domain@example.com",
        password_hash="hashed_password",  # noqa: S106 - Example hashed password for documentation
        role=FlextUserRole.USER,
        version="1.0.0",
        domain_events=[],
        metadata={},
    )

    # Value objects with validation
    FlextUsername(value="validuser")
    FlextUserEmail(value="valid@example.com")

    # Application layer

    # Infrastructure layer


def demonstrate_complete_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    # Using top-level import

    # Create auth system
    auth = FlextAuth()

    # Test user registration
    username = "testuser"
    email = "testuser@example.com"
    password = "TestPassword123!"  # noqa: S105 - Example password for documentation

    reg_result = auth.register_user(username, email, password)

    if isinstance(reg_result, dict) and "error" in reg_result:
        pass

    # Test authentication
    auth_result = auth.authenticate_user(username, password)

    if isinstance(auth_result, dict):
        if "error" in auth_result:
            pass
        elif "access_token" in auth_result:
            str(auth_result["access_token"])


def demonstrate_flext_core_integration() -> None:
    """Demonstrate integration with flext-core patterns."""
    # FlextResult pattern usage
    result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

    # FlextContainer integration
    container = FlextContainer()
    if result.success and result.data:
        container.register("auth_service", result.data)

        container.get("auth_service")


def demonstrate_type_safety() -> None:
    """Demonstrate type safety and MyPy compliance."""
    # Type-safe authentication system
    FlextAuth()

    # All FlextAuth operations return typed FlextResult objects


def show_refactoring_metrics() -> None:
    """Show quantitative metrics of the refactoring success."""
    # Calculate line counts
    project_root = Path(__file__).parent.parent
    init_file = project_root / "src" / "flext_auth" / "__init__.py"

    if init_file.exists():
        with init_file.open(encoding="utf-8") as f:
            current_lines = len(f.readlines())

        original_lines = 1929
        reduction = original_lines - current_lines
        (reduction / original_lines) * 100

        # Check specialized modules
        modules = ["decorators.py", "helpers.py", "mixins.py"]
        total_specialized = 0

        for module in modules:
            module_path = project_root / "src" / "flext_auth" / module
            if module_path.exists():
                with module_path.open(encoding="utf-8") as f:
                    lines = len(f.readlines())
                total_specialized += lines

        if current_lines + total_specialized < original_lines:
            original_lines - (current_lines + total_specialized)
        else:
            (current_lines + total_specialized) - original_lines
            # Replace ambiguous unicode info symbol for lint compliance


def main() -> None:
    """Run the complete refactored system showcase."""
    try:
        demonstrate_refactoring_benefits()
        demonstrate_modular_architecture()
        demonstrate_clean_architecture()
        demonstrate_complete_workflow()
        demonstrate_flext_core_integration()
        demonstrate_type_safety()
        show_refactoring_metrics()

    except Exception:
        traceback.print_exc()


if __name__ == "__main__":
    main()

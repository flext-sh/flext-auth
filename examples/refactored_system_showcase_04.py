"""FLEXT Auth - Refactored System Showcase (Working Version).

This example showcases the refactored FLEXT Auth system with working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_cli import u as cli_u

from flext_auth import FlextAuth, FlextAuthSettings
from flext_core import r


def _emit(message: str) -> None:
    """Emit example output through the canonical CLI facade."""
    cli_u.Cli.formatters_print(message)


class FlextAuthRefactoredSystemShowcaseExample:
    """Single owner for the refactored system showcase flow."""

    @staticmethod
    def demonstrate_refactoring_benefits() -> None:
        """Demonstrate the benefits of the refactored system."""
        auth: FlextAuth = FlextAuth()
        auth.register_user("modern_user", "modern@example.com", "ModernPass123!")
        auth_result = auth.authenticate_user("modern_user", "ModernPass123!")
        if auth_result.success:
            auth_data = auth_result.value
            user_name = auth_data.name
            _emit(f"Authenticated user: {user_name}")

    @staticmethod
    def demonstrate_quickstart_functionality() -> None:
        """Demonstrate quick start behavior via FlextAuth public API."""
        auth_service = FlextAuth.quick_start(create_admin_user=False)
        quickstart_result = auth_service.register_user(
            "quickstart_user", "quickstart@example.com", "QuickstartPassword123!"
        )
        if quickstart_result.success:
            created_identity = quickstart_result.value
            _emit(f"Quickstart identity created: {created_identity.name}")

    @staticmethod
    def demonstrate_flext_result_integration() -> None:
        """Demonstrate r pattern integration."""
        _ = r[str].ok("Refactoring successful")
        _ = r[str].fail("Example failure case")
        auth: FlextAuth = FlextAuth()
        auth.authenticate_user("test_user", "password")

    @staticmethod
    def demonstrate_system_architecture() -> None:
        """Demonstrate the clean system architecture."""
        _ = FlextAuth()
        _ = FlextAuthSettings()

    @staticmethod
    def demonstrate_error_handling() -> None:
        """Demonstrate proper error handling patterns."""
        auth: FlextAuth = FlextAuth()
        auth.register_user("weakuser", "weak@example.com", "123")
        auth.authenticate_user("nonexistent", "password")

    @classmethod
    def main(cls) -> None:
        """Execute refactored system showcase."""
        cls.demonstrate_refactoring_benefits()
        cls.demonstrate_quickstart_functionality()
        cls.demonstrate_flext_result_integration()
        cls.demonstrate_system_architecture()
        cls.demonstrate_error_handling()


if __name__ == "__main__":
    FlextAuthRefactoredSystemShowcaseExample.main()

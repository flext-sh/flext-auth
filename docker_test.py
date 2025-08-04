#!/usr/bin/env python3  # noqa: EXE001
"""Docker validation test for FLEXT Auth.

This script validates that all examples work correctly in a Docker environment.
Tests the core functionality without requiring the full API setup.
"""

import sys
import traceback


def test_basic_imports() -> bool | None:
    """Test that all basic imports work."""
    try:
        from flext_auth import (
            ADMIN_ROLE,
            USER_ROLE,
            FlextAuth,
            flext_auth_hash_password,
            flext_auth_quick_start,
            flext_auth_validate_email,
        )

        return True
    except ImportError:
        return False


def test_basic_functionality() -> bool | None:
    """Test basic authentication functionality."""
    try:
        from flext_auth import (
            FlextAuth,
            flext_auth_hash_password,
            flext_auth_validate_email,
        )

        # Test password hashing
        password = "TestPassword123!"
        flext_auth_hash_password(password, rounds=4)  # Fast for testing

        # Test email validation
        flext_auth_validate_email("test@example.com")
        flext_auth_validate_email("invalid-email")

        # Test FlextAuth instantiation
        FlextAuth()

        return True
    except Exception:
        traceback.print_exc()
        return False


def test_quick_start() -> bool | None:
    """Test quick start functionality."""
    try:
        from flext_auth import flext_auth_quick_start

        result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        if result.is_success:
            pass

        return result.is_success
    except Exception:
        traceback.print_exc()
        return False


def test_examples_core_functionality() -> bool | None:
    """Test that core functionality from examples works."""
    try:
        # Test configuration
        from flext_auth.config import AppConfig

        AppConfig()

        # Test domain entities
        from flext_auth.domain.value_objects import FlextUserEmail, FlextUsername

        FlextUsername(value="testuser")
        FlextUserEmail(value="test@example.com")

        return True
    except Exception:
        traceback.print_exc()
        return False


def main() -> int:
    """Run all Docker validation tests."""
    tests = [
        ("Basic Imports", test_basic_imports),
        ("Basic Functionality", test_basic_functionality),
        ("Quick Start", test_quick_start),
        ("Examples Core", test_examples_core_functionality),
    ]

    results = []
    for test_name, test_func in tests:
        success = test_func()
        results.append((test_name, success))

    all_passed = True
    for test_name, success in results:
        if not success:
            all_passed = False

    if all_passed:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Docker validation test for FLEXT Auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
import traceback

from flext_auth import (
    ADMIN_ROLE,
    USER_ROLE,
    AppConfig,
    FlextAuth,
    FlextUserEmail,
    FlextUsername,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_email,
)


def test_basic_imports() -> bool | None:
    """Test that all basic imports work."""
    try:
        # All imports are now at top-level
        _ = (
            ADMIN_ROLE,
            USER_ROLE,
            FlextAuth,
            flext_auth_hash_password,
            flext_auth_quick_start,
            flext_auth_validate_email,
        )

        # Suppress unused import warnings
        _ = (
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
        # All imports are now at top-level
        if flext_auth_hash_password is None:
            return False

        # Test password hashing
        password = "TestPassword123!"
        flext_auth_hash_password(password, rounds=4)  # Fast for testing

        # Test email validation
        if flext_auth_validate_email is not None:
            flext_auth_validate_email("test@example.com")
            flext_auth_validate_email("invalid-email")

        # Test FlextAuth instantiation
        if FlextAuth is not None:
            FlextAuth()

        return True
    except Exception:
        traceback.print_exc()
        return False


def test_quick_start() -> bool | None:
    """Test quick start functionality."""
    try:
        # All imports are now at top-level
        if flext_auth_quick_start is None:
            return False

        result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        if result.success:
            pass

        return result.success
    except Exception:
        traceback.print_exc()
        return False


def test_examples_core_functionality() -> bool | None:
    """Test that core functionality from examples works."""
    try:
        # All imports are now at top-level
        if AppConfig is None or FlextUserEmail is None or FlextUsername is None:
            return False

        # Test configuration
        AppConfig()

        # Test domain entities
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
    for _, success in results:
        if not success:
            all_passed = False

    if all_passed:
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())

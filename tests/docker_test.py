#!/usr/bin/env python3
"""Docker validation test for FLEXT Auth.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
import traceback

from flext_auth import (
    FlextAuth,
    FlextAuthConstants,
    FlextPasswordService,
)
from flext_auth.utilities import FlextAuthUtilities


def test_basic_imports() -> None:
    """Test that all basic imports work."""
    try:
        # Test real classes
        _ = (
            FlextAuth,
            FlextAuthConstants,
            FlextPasswordService,
            FlextAuthUtilities,
        )
        assert True
    except ImportError:
        msg = "Import failed"
        raise AssertionError(msg)


def test_basic_functionality() -> None:
    """Test basic authentication functionality."""
    try:
        # Test password hashing using real class
        password_service = FlextPasswordService()
        password = "TestPassword123!"
        hash_result = password_service.hash_password(
            password, rounds=4
        )  # Fast for testing
        assert hash_result.success, "Password hashing failed"

        # Test email validation using real class
        email_result = FlextAuthUtilities.validate_email("test@example.com")
        assert email_result.success, "Valid email validation failed"

        # Test invalid email
        invalid_result = FlextAuthUtilities.validate_email("invalid-email")
        assert not invalid_result.success, "Invalid email should fail validation"

        # Test FlextAuth instantiation
        auth = FlextAuth()
        assert auth is not None, "FlextAuth instantiation failed"
    except Exception:
        traceback.print_exc()
        msg = "Test failed"
        raise AssertionError(msg)


def test_quick_start() -> None:
    """Test quick start functionality."""
    try:
        # Use FlextAuth.quick_start method
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert auth is not None, "FlextAuth.quick_start failed"

        # Verify it's a FlextAuth instance
        assert isinstance(auth, FlextAuth), (
            "FlextAuth.quick_start should return FlextAuth instance"
        )
    except Exception:
        traceback.print_exc()
        msg = "Test failed"
        raise AssertionError(msg)


def test_examples_core_functionality() -> None:
    """Test that core functionality from examples works."""
    try:
        # Test constants availability
        REDACTED_LDAP_BIND_PASSWORD_role = FlextAuthConstants.ROLE_ADMIN
        user_role = FlextAuthConstants.ROLE_USER
        assert REDACTED_LDAP_BIND_PASSWORD_role and user_role, "Constants not available"

        # Test password service functionality
        password_service = FlextPasswordService()
        test_password = "TestPassword123!"
        strength_result = password_service.validate_password_strength(test_password)
        assert strength_result.success, "Password strength validation failed"

        # Test utilities
        secure_password = FlextAuthUtilities.generate_secure_password(16)
        assert secure_password and len(secure_password) == 16, (
            "Secure password generation failed"
        )
    except Exception:
        traceback.print_exc()
        msg = "Test failed"
        raise AssertionError(msg)


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

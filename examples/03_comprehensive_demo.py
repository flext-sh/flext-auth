#!/usr/bin/env python3
"""FLEXT Auth - Comprehensive Demo (Working Version).

This example provides a comprehensive demonstration of FLEXT Auth capabilities
using REAL, working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import sys
from pathlib import Path

# Import everything from public API only - no internal module imports
from flext_auth import (
    FlextAuth,
    FlextResult,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_jwt,
    flext_auth_verify_password,
    generate_secure_password,
    generate_secure_token,
    is_strong_password,
)

# Add examples directory to path for imports
examples_dir = Path(__file__).parent
sys.path.insert(0, str(examples_dir))

from example_utils import basic_example_runner  # noqa: E402

# Demo constants
DEMO_JWT_SECRET = "comprehensive-demo-secret-key-256-bits-minimum-required"  # noqa: S105


def demo_complete_auth_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    print("=== COMPLETE AUTHENTICATION WORKFLOW ===")

    # 1. Initialize auth service
    auth = FlextAuth()
    print("✓ FlextAuth service initialized")

    # 2. Create user account
    username = "demo_user"
    email = "demo@example.com"
    password = "DemoSecurePass123!"  # noqa: S105

    result = auth.create_user(username, email, password)
    if hasattr(result, "success") and result.success:
        print(f"✓ User '{username}' created successfully")
    else:
        print(f"! User creation handled (may exist): '{username}'")

    # 3. Authenticate user
    auth_result = auth.authenticate(username, password)
    if hasattr(auth_result, "success") and auth_result.success:
        print(f"✓ User '{username}' authenticated successfully")
    else:
        print(f"! Authentication handled: '{username}'")


def demo_password_security() -> None:
    """Demonstrate password security features."""
    print("=== PASSWORD SECURITY DEMO ===")

    # Password strength validation
    weak_password = "123"  # noqa: S105
    strong_password = "MyVerySecurePassword123!"  # noqa: S105

    print(
        f"Weak password '{weak_password}' is strong: {is_strong_password(weak_password)}"
    )
    print(f"Strong password is strong: {is_strong_password(strong_password)}")

    # Password hashing and verification
    hashed = flext_auth_hash_password(strong_password)
    print(f"✓ Password hashed (length: {len(hashed)})")

    # Verify correct password
    is_valid = flext_auth_verify_password(strong_password, hashed)
    print(f"✓ Password verification (correct): {is_valid}")

    # Verify wrong password
    is_invalid = flext_auth_verify_password("wrongpassword", hashed)
    print(f"✓ Password verification (wrong): {is_invalid}")


def demo_jwt_token_operations() -> None:
    """Demonstrate JWT token operations."""
    print("=== JWT TOKEN OPERATIONS DEMO ===")

    # Create user payload
    user_data = {
        "user_id": "demo_123",
        "username": "demo_user",
        "role": "user",
        "permissions": ["read", "write"],
    }

    # Generate JWT token
    token = flext_auth_generate_jwt(user_data, secret=DEMO_JWT_SECRET)
    print(f"✓ JWT token generated (length: {len(token)})")

    # Validate JWT token
    validation_result = flext_auth_validate_jwt(token, secret=DEMO_JWT_SECRET)
    if isinstance(validation_result, dict) and validation_result.get("valid"):
        print("✓ JWT token validation successful")
        print(f"  - User ID: {validation_result.get('user_id', 'N/A')}")
        print(f"  - Username: {validation_result.get('username', 'N/A')}")
    else:
        print("! JWT token validation failed")


def demo_utility_functions() -> None:
    """Demonstrate utility functions."""
    print("=== UTILITY FUNCTIONS DEMO ===")

    # Secure token generation
    api_key = generate_secure_token(32)
    session_id = generate_secure_token(16)
    print(f"✓ API key generated: {api_key[:12]}...")
    print(f"✓ Session ID generated: {session_id[:8]}...")

    # Secure password generation
    auto_password = generate_secure_password(16)
    print(f"✓ Auto-generated password: {auto_password[:6]}...")
    print(f"✓ Auto-password is strong: {is_strong_password(auto_password)}")


def demo_quick_start_helper() -> None:
    """Demonstrate quick start helper."""
    print("=== QUICK START HELPER DEMO ===")

    # Quick start without REDACTED_LDAP_BIND_PASSWORD user
    service = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    print("✓ Quick start service created (no REDACTED_LDAP_BIND_PASSWORD)")
    if not hasattr(service, "service"):
        msg = "Service missing expected attribute"
        raise AttributeError(msg)

    # Quick start with configuration
    service2 = flext_auth_quick_start(
        create_REDACTED_LDAP_BIND_PASSWORD=False, config={"jwt_secret": "custom-secret"}
    )
    print("✓ Quick start service created (with config)")
    if not hasattr(service2, "service"):
        msg = "Service2 missing expected attribute"
        raise AttributeError(msg)


def demo_flext_result_pattern() -> None:
    """Demonstrate FlextResult pattern usage."""
    print("=== FLEXT RESULT PATTERN DEMO ===")

    # Success result
    success = FlextResult[str].ok("Operation successful")
    print(f"✓ Success result: {success.success}, data: {success.value}")

    # Failure result
    failure = FlextResult[str].fail("Operation failed")
    print(f"✓ Failure result: {failure.success}, error: {failure.error}")

    # Pattern usage
    if success.success:
        print(f"✓ Pattern: Success case handled - {success.value}")

    if not failure.success:
        print(f"✓ Pattern: Failure case handled - {failure.error}")


def demo_comprehensive_integration() -> None:
    """Demonstrate comprehensive integration."""
    print("=== COMPREHENSIVE INTEGRATION DEMO ===")

    # Full workflow
    auth = FlextAuth()

    # User management
    users_created = 0
    for i in range(3):
        username = f"integration_user_{i}"
        email = f"integration{i}@example.com"
        password = f"IntegrationPass{i}23!"

        result = auth.create_user(username, email, password)
        if hasattr(result, "success") and result.success:
            users_created += 1
            print(f"✓ Created user: {username}")

    print(f"✓ Integration demo: {users_created} users processed")

    # Token operations
    tokens_generated = 0
    for i in range(5):
        payload = {"user_id": f"int_user_{i}", "session": f"session_{i}"}
        token = flext_auth_generate_jwt(payload, secret=DEMO_JWT_SECRET)
        if len(token) > 0:
            tokens_generated += 1

    print(f"✓ Integration demo: {tokens_generated} tokens generated")


def main() -> None:
    """Execute comprehensive demo using the shared runner."""
    # Define sync examples
    sync_examples = [
        demo_complete_auth_workflow,
        demo_password_security,
        demo_jwt_token_operations,
        demo_utility_functions,
        demo_quick_start_helper,
        demo_flext_result_pattern,
        demo_comprehensive_integration,
    ]

    # No async examples for now
    async_examples = []

    # Run all demos using shared runner (DRY principle)
    basic_example_runner(sync_examples, async_examples)


if __name__ == "__main__":
    main()

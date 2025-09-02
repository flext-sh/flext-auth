#!/usr/bin/env python3
"""FLEXT Auth - Comprehensive Demo (Working Version).

This example provides a comprehensive demonstration of FLEXT Auth capabilities
using REAL, working functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os

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
)

from .utils import basic_example_runner

DEMO_JWT_SECRET = os.getenv(
    "FLEXT_DEMO_JWT_SECRET", "comprehensive-demo-secret-key-256-bits-minimum-required"
)


def demo_complete_auth_workflow() -> None:
    """Demonstrate complete authentication workflow."""
    # 1. Initialize auth service
    auth = FlextAuth()

    # 2. Create user account
    username = "demo_user"
    email = "demo@example.com"
    password = os.getenv("FLEXT_DEMO_USER_PASSWORD", "DemoSecurePass123!")

    result = auth.create_user(username, email, password)
    if hasattr(result, "success") and result.success:
        pass

    # 3. Authenticate user
    auth_result = auth.authenticate(username, password)
    if hasattr(auth_result, "success") and auth_result.success:
        pass


def demo_password_security() -> None:
    """Demonstrate password security features."""
    # Password strength validation
    strong_password = os.getenv(
        "FLEXT_DEMO_STRONG_PASSWORD", "MyVerySecurePassword123!"
    )

    # Password hashing and verification
    hashed = flext_auth_hash_password(strong_password)

    # Verify correct password
    flext_auth_verify_password(strong_password, hashed)

    # Verify wrong password
    flext_auth_verify_password("wrongpassword", hashed)


def demo_jwt_token_operations() -> None:
    """Demonstrate JWT token operations."""
    # Create user payload
    user_data = {
        "user_id": "demo_123",
        "username": "demo_user",
        "role": "user",
        "permissions": ["read", "write"],
    }

    # Generate JWT token
    token = flext_auth_generate_jwt(user_data, secret=DEMO_JWT_SECRET)

    # Validate JWT token
    validation_result = flext_auth_validate_jwt(token, secret=DEMO_JWT_SECRET)
    if isinstance(validation_result, dict) and validation_result.get("valid"):
        pass


def demo_utility_functions() -> None:
    """Demonstrate utility functions."""
    # Secure token generation
    generate_secure_token(32)
    generate_secure_token(16)

    # Secure password generation
    generate_secure_password(16)


def demo_quick_start_helper() -> None:
    """Demonstrate quick start helper."""
    # Quick start without REDACTED_LDAP_BIND_PASSWORD user
    service = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    if not hasattr(service, "service"):
        msg = "Service missing expected attribute"
        raise AttributeError(msg)

    # Quick start with configuration
    service2 = flext_auth_quick_start(
        create_REDACTED_LDAP_BIND_PASSWORD=False, config={"jwt_secret": "custom-secret"}
    )
    if not hasattr(service2, "service"):
        msg = "Service2 missing expected attribute"
        raise AttributeError(msg)


def demo_flext_result_pattern() -> None:
    """Demonstrate FlextResult pattern usage."""
    # Success result
    success = FlextResult[str].ok("Operation successful")

    # Failure result
    failure = FlextResult[str].fail("Operation failed")

    # Pattern usage
    if success.success:
        pass

    if not failure.success:
        pass


def demo_comprehensive_integration() -> None:
    """Demonstrate comprehensive integration."""
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

    # Token operations
    tokens_generated = 0
    for i in range(5):
        payload = {"user_id": f"int_user_{i}", "session": f"session_{i}"}
        token = flext_auth_generate_jwt(payload, secret=DEMO_JWT_SECRET)
        if len(token) > 0:
            tokens_generated += 1


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

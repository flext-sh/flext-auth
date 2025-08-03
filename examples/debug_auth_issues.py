#!/usr/bin/env python3
"""Debug Authentication Issues.

Diagnose and fix specific problems found:
1. Password hashing/verification failure
2. JWT user_id empty issue

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth.helpers import (
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_validate_jwt,
    flext_auth_verify_password,
)
from flext_auth.jwt import FlextJWTService
from flext_auth.services.password_service import FlextPasswordService


def debug_password_service() -> None:
    """Debug password hashing issue."""
    print("🔍 DEBUG: Password Service")
    print("-" * 30)

    password = "TestPassword123!"

    # Test direct service
    print("1. Direct FlextPasswordService:")
    service = FlextPasswordService(rounds=4)  # Fast for debugging
    hash_result = service.hash_password(password)

    print(f"   Hash result success: {hash_result.is_success}")
    if hash_result.is_success and hash_result.data:
        hashed = str(hash_result.data)
        print(f"   Hash length: {len(hashed)}")
        print(f"   Hash preview: {hashed[:50]}...")

        # Test verification
        verify_result = service.verify_password(password, hashed)
        print(f"   Verify result success: {verify_result.is_success}")
        print(f"   Verify result data: {verify_result.data}")
    else:
        print(f"   Hash error: {hash_result.error}")

    # Test helper functions
    print("\n2. Helper functions:")
    try:
        helper_hash = flext_auth_hash_password(password, rounds=4)
        print(f"   Helper hash length: {len(helper_hash)}")
        print(f"   Helper hash preview: {helper_hash[:50]}...")

        helper_verify = flext_auth_verify_password(password, helper_hash)
        print(f"   Helper verification: {helper_verify}")
    except Exception as e:
        print(f"   Helper error: {e}")


def debug_jwt_service() -> None:
    """Debug JWT user_id issue."""
    print("\n🔍 DEBUG: JWT Service")
    print("-" * 30)

    payload = {"user_id": "test123", "username": "testuser", "role": "REDACTED_LDAP_BIND_PASSWORD"}

    # Test direct service
    print("1. Direct FlextJWTService:")
    service = FlextJWTService(secret_key="test-secret")

    # Test access token generation
    access_result = service.generate_access_token(
        user_id=payload["user_id"], username=payload["username"], role=payload["role"]
    )

    print(f"   Access token success: {access_result.is_success}")
    if access_result.is_success and access_result.data:
        token = access_result.data
        print(f"   Token preview: {token[:50]}...")

        # Test verification
        verify_result = service.verify_token(token)
        print(f"   Verify success: {verify_result.is_success}")
        if verify_result.is_success and verify_result.data:
            claims = verify_result.data
            print(f"   Claims type: {type(claims)}")
            print(f"   Claims user_id: {getattr(claims, 'user_id', 'NOT_FOUND')}")
            print(f"   Claims sub: {getattr(claims, 'sub', 'NOT_FOUND')}")
            print(f"   Claims username: {getattr(claims, 'username', 'NOT_FOUND')}")
        else:
            print(f"   Verify error: {verify_result.error}")
    else:
        print(f"   Access token error: {access_result.error}")

    # Test helper functions
    print("\n2. Helper functions:")
    helper_token_result = flext_auth_generate_jwt(payload)
    print(f"   Helper token success: {helper_token_result.is_success}")
    if helper_token_result.is_success and helper_token_result.data:
        helper_token = helper_token_result.data
        print(f"   Helper token preview: {helper_token[:50]}...")

        helper_validate = flext_auth_validate_jwt(helper_token)
        print(f"   Helper validate success: {helper_validate.is_success}")
        if helper_validate.is_success and helper_validate.data:
            decoded = helper_validate.data
            print(f"   Helper decoded: {decoded}")


def main() -> None:
    """Run debug diagnostics."""
    print("🛠️  FLEXT-AUTH DEBUG DIAGNOSTICS")
    print("=" * 50)

    debug_password_service()
    debug_jwt_service()


if __name__ == "__main__":
    main()

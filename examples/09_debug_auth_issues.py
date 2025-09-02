#!/usr/bin/env python3
"""Debug Authentication Issues.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import (
    FlextJWTService,
    FlextPasswordService,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_validate_jwt,
)


def debug_password_service() -> None:
    """Debug password hashing issue."""
    password = "TestPassword123!"

    # Test direct service
    service = FlextPasswordService()  # Fast for debugging
    hash_result = service.hash_password(password, rounds=4)

    if hash_result.success and hash_result.value:
        hashed = str(hash_result.value)

        # Test verification
        verify_result = service.verify_password(password, hashed)
        if verify_result.success:
            print(f"Password verification: {verify_result.value}")

    # Test helper functions
    helper_hash_result = flext_auth_hash_password(password, rounds=4)
    if helper_hash_result.success and helper_hash_result.value:
        helper_hash = helper_hash_result.value
        helper_verify_result = service.verify_password(password, helper_hash)
        if helper_verify_result.success:
            print(f"Helper hash verification: {helper_verify_result.value}")


def debug_jwt_service() -> None:
    """Debug JWT user_id issue."""
    payload: dict[str, object] = {
        "user_id": "test123",
        "username": "testuser",
        "role": "REDACTED_LDAP_BIND_PASSWORD",
    }
    jwt_secret = "test-secret"

    # Test direct service
    service = FlextJWTService(secret=jwt_secret)

    # Test token generation
    token_result = service.generate_token(claims=payload, expires_minutes=30)

    if token_result.success and token_result.value:
        token = token_result.value
        print(f"Generated token: {token[:20]}...")

        # Test verification
        verify_result = service.validate_token(token)
        if verify_result.success and verify_result.value:
            print(f"Token validation successful: {verify_result.value}")

    # Test helper functions
    helper_token_result = flext_auth_generate_jwt(
        user_id=str(payload["user_id"]),
        username=str(payload["username"]),
        role=str(payload["role"]),
        session_id="session123",
        jwt_secret=jwt_secret,
        expiry_minutes=30,
    )
    if helper_token_result.success and helper_token_result.value:
        helper_token = helper_token_result.value
        print(f"Helper token: {helper_token[:20]}...")

        helper_validate = flext_auth_validate_jwt(helper_token, jwt_secret)
        if helper_validate.success and helper_validate.value:
            print(f"Helper validation successful: {helper_validate.value}")


def main() -> None:
    """Run debug diagnostics."""
    debug_password_service()
    debug_jwt_service()


if __name__ == "__main__":
    main()

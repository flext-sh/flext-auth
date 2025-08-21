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
    flext_auth_verify_password,
)


def debug_password_service() -> None:
    """Debug password hashing issue."""
    password = "TestPassword123!"  # noqa: S105 - Example password for documentation

    # Test direct service
    service = FlextPasswordService(rounds=4)  # Fast for debugging
    hash_result = service.hash_password(password)

    if hash_result.success and hash_result.value:
        hashed = str(hash_result.value)

        # Test verification
        service.verify_password(password, hashed)

    # Test helper functions
    helper_hash = flext_auth_hash_password(password, rounds=4)

    flext_auth_verify_password(password, helper_hash)


def debug_jwt_service() -> None:
    """Debug JWT user_id issue."""
    payload = {"user_id": "test123", "username": "testuser", "role": "REDACTED_LDAP_BIND_PASSWORD"}

    # Test direct service
    service = FlextJWTService(secret_key="test-secret")  # noqa: S106 - Example secret for debugging

    # Test access token generation
    access_result = service.generate_access_token(
        user_id=payload["user_id"],
        username=payload["username"],
        role=payload["role"],
    )

    if access_result.success and access_result.value:
        token = access_result.value

        # Test verification
        verify_result = service.verify_token(token)
        if verify_result.success and verify_result.value:
            pass

    # Test helper functions
    helper_token_result = flext_auth_generate_jwt(payload)
    if helper_token_result.success and helper_token_result.value:
        helper_token = helper_token_result.value

        helper_validate = flext_auth_validate_jwt(helper_token)
        if helper_validate.success and helper_validate.value:
            pass


def main() -> None:
    """Run debug diagnostics."""
    debug_password_service()
    debug_jwt_service()


if __name__ == "__main__":
    main()

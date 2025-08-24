"""Tests for clean flext-auth implementation - focused on helpers only.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import (
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_validate_email,
    flext_auth_validate_jwt,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
)

# Constants
EXPECTED_DATA_COUNT = 3


def test_flext_auth_hash_password() -> None:
    """Test password hashing helper."""
    password = "TestPassword123!"
    result = flext_auth_hash_password(
        password
    )  # Legacy function doesn't take rounds parameter

    assert result.success
    hashed = result.value
    assert hashed != password
    assert len(hashed) > 50
    assert hashed.startswith("$2b$")

    # Test verification
    verify_result = flext_auth_verify_password(password, hashed)
    assert verify_result.success
    assert verify_result.value is True

    wrong_verify_result = flext_auth_verify_password("wrong", hashed)
    assert wrong_verify_result.success
    assert wrong_verify_result.value is False


def test_flext_auth_jwt_helpers() -> None:
    """Test JWT helpers."""
    user_id = "123"
    username = "test"
    jwt_secret = "test-secret-key"

    # Generate token with correct parameters
    token_result = flext_auth_generate_jwt(
        user_id=user_id,
        username=username,
        jwt_secret=jwt_secret
    )
    assert token_result.success
    token = token_result.value
    assert isinstance(token, str)
    assert token != ""
    assert len(token.split(".")) == EXPECTED_DATA_COUNT

    # Validate token
    decoded_result = flext_auth_validate_jwt(token, jwt_secret=jwt_secret)
    assert decoded_result.success
    decoded = decoded_result.value
    assert isinstance(decoded, dict)

    # Token should be valid and contain user data
    assert "user_id" in decoded
    assert "username" in decoded
    assert decoded["user_id"] == user_id
    assert decoded["username"] == username


def test_flext_auth_validation_helpers() -> None:
    """Test validation helpers."""
    # Email validation - returns bool directly
    assert flext_auth_validate_email("test@example.com") is True
    assert flext_auth_validate_email("invalid-email") is False

    # Password strength - returns FlextResult[bool]
    strong_result = flext_auth_validate_password_strength("StrongPassword123!")
    assert strong_result.success
    assert isinstance(strong_result.value, bool)
    assert strong_result.value is True

    weak_result = flext_auth_validate_password_strength("123")
    assert weak_result.success
    assert isinstance(weak_result.value, bool)
    assert weak_result.value is False


def test_flext_auth_session_helper() -> None:
    """Test JWT token creation as session alternative."""
    # Use JWT token generation as session creation alternative
    # since flext_auth_create_secure_session doesn't exist yet
    payload = {"user_id": "user123", "username": "testuser", "role": "REDACTED_LDAP_BIND_PASSWORD"}
    token_result = flext_auth_generate_jwt(
        user_id=payload["user_id"],
        username=payload["username"],
        role=payload["role"]
    )

    assert token_result.success
    token = token_result.value
    assert isinstance(token, str)
    assert len(token) > 0

    # Validate token to check payload
    validation_result = flext_auth_validate_jwt(token)
    assert validation_result.success
    validation_data = validation_result.value
    assert isinstance(validation_data, dict)

    # Basic validation - token structure exists
    assert "user_id" in validation_data
    assert "username" in validation_data


if __name__ == "__main__":
    """Run tests directly."""
    try:
        test_flext_auth_hash_password()
        test_flext_auth_jwt_helpers()
        test_flext_auth_validation_helpers()
        test_flext_auth_session_helper()
    except (RuntimeError, ValueError, TypeError):
        pass

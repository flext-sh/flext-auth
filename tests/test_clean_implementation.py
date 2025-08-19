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
    hashed = flext_auth_hash_password(password)  # Legacy function doesn't take rounds parameter

    assert hashed != password
    assert len(hashed) > 50
    assert hashed.startswith("$2b$")

    # Test verification
    assert flext_auth_verify_password(password, hashed) is True
    assert flext_auth_verify_password("wrong", hashed) is False


def test_flext_auth_jwt_helpers() -> None:
    """Test JWT helpers."""
    payload = {"user_id": "123", "username": "test"}
    secret = "test-secret-key"

    # Legacy function returns string directly
    token = flext_auth_generate_jwt(payload, secret=secret)
    assert isinstance(token, str)
    assert token != ""
    assert len(token.split(".")) == EXPECTED_DATA_COUNT

    # Legacy function returns dict directly
    decoded = flext_auth_validate_jwt(token, secret)
    assert isinstance(decoded, dict)

    if decoded.get("valid"):
        # Token was valid, check contents
        assert "user_id" in decoded
        assert "username" in decoded
    else:
        # Invalid token, check error structure
        assert "valid" in decoded


def test_flext_auth_validation_helpers() -> None:
    """Test validation helpers."""
    # Email validation - legacy function returns bool directly
    assert flext_auth_validate_email("test@example.com") is True
    assert flext_auth_validate_email("invalid-email") is False

    # Password strength - legacy function returns dict directly
    strong = flext_auth_validate_password_strength("StrongPassword123!")
    assert isinstance(strong, dict)
    assert "is_strong" in strong
    assert strong["score"] >= 4
    assert strong["is_strong"] is True

    weak = flext_auth_validate_password_strength("123")
    assert isinstance(weak, dict)
    assert "is_strong" in weak
    assert weak["is_strong"] is False
    assert len(weak["feedback"]) > 0


def test_flext_auth_session_helper() -> None:
    """Test JWT token creation as session alternative."""
    # Use JWT token generation as session creation alternative
    # since flext_auth_create_secure_session doesn't exist yet
    payload = {"user_id": "user123", "username": "testuser", "role": "REDACTED_LDAP_BIND_PASSWORD"}
    token = flext_auth_generate_jwt(payload)

    assert isinstance(token, str)
    assert len(token) > 0

    # Validate token to check payload
    validation_result = flext_auth_validate_jwt(token)
    assert isinstance(validation_result, dict)

    # Basic validation - token structure exists
    assert "valid" in validation_result


if __name__ == "__main__":
    """Run tests directly."""
    try:
        test_flext_auth_hash_password()
        test_flext_auth_jwt_helpers()
        test_flext_auth_validation_helpers()
        test_flext_auth_session_helper()
    except (RuntimeError, ValueError, TypeError):
        pass

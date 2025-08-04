"""Tests for clean flext-auth implementation - focused on helpers only.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import (
    flext_auth_create_secure_session,
    flext_auth_decode_jwt,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
)

# Constants
EXPECTED_DATA_COUNT = 3


def test_flext_auth_hash_password() -> None:
    """Test password hashing helper."""
    password = "TestPassword123!"
    hashed = flext_auth_hash_password(password, rounds=4)

    assert hashed != password
    assert len(hashed) > 50
    assert hashed.startswith("$2b$")

    # Test verification
    if not (flext_auth_verify_password(password, hashed)):
        raise AssertionError(
            f"Expected True, got {flext_auth_verify_password(password, hashed)}"
        )
    if flext_auth_verify_password("wrong", hashed):
        raise AssertionError(
            f"Expected False, got {flext_auth_verify_password('wrong', hashed)}"
        )


def test_flext_auth_jwt_helpers() -> None:
    """Test JWT helpers."""
    payload = {"user_id": "123", "username": "test"}
    secret = "test-secret-key"

    token_result = flext_auth_generate_jwt(payload, secret=secret)
    assert token_result.success, f"JWT generation failed: {token_result.error}"
    token = token_result.data
    assert token != ""
    if len(token.split(".")) != EXPECTED_DATA_COUNT:
        raise AssertionError(f"Expected {3}, got {len(token.split('.'))}")

    decoded_result = flext_auth_decode_jwt(token, secret)
    assert decoded_result.success, f"JWT decode failed: {decoded_result.error}"
    decoded = decoded_result.data
    assert decoded is not None
    if decoded["user_id"] != "123":
        raise AssertionError(f"Expected {'123'}, got {decoded['user_id']}")
    assert decoded["username"] == "test"


def test_flext_auth_validation_helpers() -> None:
    """Test validation helpers."""
    # Email validation
    if not (flext_auth_validate_email("test@example.com")):
        raise AssertionError(
            f"Expected True, got {flext_auth_validate_email('test@example.com')}"
        )
    if flext_auth_validate_email("invalid-email"):
        raise AssertionError(
            f"Expected False, got {flext_auth_validate_email('invalid-email')}"
        )

    # Password strength
    strong = flext_auth_validate_password_strength("StrongPassword123!")
    if not (strong["valid"]):
        raise AssertionError(f"Expected True, got {strong['valid']}")
    if strong["score"] < 4:
        raise AssertionError(f"Expected {strong['score']} >= {4}")

    weak = flext_auth_validate_password_strength("123")
    if weak["valid"]:
        raise AssertionError(f"Expected False, got {weak['valid']}")
    assert len(weak["feedback"]) > 0


def test_flext_auth_session_helper() -> None:
    """Test session creation helper."""
    session = flext_auth_create_secure_session("user123", "testuser", "REDACTED_LDAP_BIND_PASSWORD", 24)

    if session["user_id"] != "user123":
        raise AssertionError(f"Expected {'user123'}, got {session['user_id']}")
    assert session["username"] == "testuser"
    if session["role"] != "REDACTED_LDAP_BIND_PASSWORD":
        raise AssertionError(f"Expected {'REDACTED_LDAP_BIND_PASSWORD'}, got {session['role']}")
    assert len(session["session_id"]) > 20
    if not (session["is_active"]):
        raise AssertionError(f"Expected True, got {session['is_active']}")
    if "created_at" not in session:
        raise AssertionError(f"Expected {'created_at'} in {session}")
    assert "expires_at" in session


if __name__ == "__main__":
    """Run tests directly."""
    try:
        test_flext_auth_hash_password()
        test_flext_auth_jwt_helpers()
        test_flext_auth_validation_helpers()
        test_flext_auth_session_helper()
    except (RuntimeError, ValueError, TypeError):
        pass

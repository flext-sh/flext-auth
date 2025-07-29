"""Tests for working flext-auth helpers - FUNCTIONAL VERSION."""

import sys

sys.path.insert(0, "/home/marlonsc/flext/flext-auth/src")

from flext_auth.core_helpers import (
    FLEXT_AUTH_ADMIN,
    FLEXT_AUTH_USER,
    flext_auth_complete_validation_workflow,
    flext_auth_create_secure_session,
    flext_auth_decode_jwt,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_token_validation,
    flext_auth_validate_email,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
)


def test_password_helpers() -> None:
    """Test password hashing and verification."""
    password = "TestPassword123!"

    # Hash password
    hashed = flext_auth_hash_password(password, rounds=4)
    assert hashed != password
    assert len(hashed) > 50
    assert hashed.startswith("$2b$")

    # Verify password
    assert flext_auth_verify_password(password, hashed) is True
    assert flext_auth_verify_password("wrong", hashed) is False


def test_jwt_helpers() -> None:
    """Test JWT generation and decoding."""
    payload = {"user_id": "123", "username": "test", "role": "REDACTED_LDAP_BIND_PASSWORD"}
    secret = "test-secret-key"

    # Generate JWT
    token = flext_auth_generate_jwt(payload, secret=secret, expires_minutes=60)
    assert token != ""
    assert len(token.split(".")) == 3

    # Decode JWT
    decoded = flext_auth_decode_jwt(token, secret)
    assert decoded is not None
    assert decoded["user_id"] == "123"
    assert decoded["username"] == "test"
    assert decoded["role"] == "REDACTED_LDAP_BIND_PASSWORD"
    assert "iat" in decoded
    assert "exp" in decoded

    # Test invalid token
    invalid = flext_auth_decode_jwt("invalid.token.123", secret)
    assert invalid is None


def test_validation_helpers() -> None:
    """Test email and password validation."""
    # Email validation
    assert flext_auth_validate_email("test@example.com") is True
    assert flext_auth_validate_email("user@domain.co.uk") is True
    assert flext_auth_validate_email("invalid-email") is False
    assert flext_auth_validate_email("@domain.com") is False

    # Password strength validation
    strong = flext_auth_validate_password_strength("StrongPassword123!")
    assert strong["valid"] is True
    assert strong["score"] >= 4
    assert strong["strength"] in {"good", "strong"}
    assert len(strong["feedback"]) == 0

    weak = flext_auth_validate_password_strength("123")
    assert weak["valid"] is False
    assert weak["score"] < 4
    assert len(weak["feedback"]) > 0
    assert "At least 8 characters required" in weak["feedback"]


def test_session_helper() -> None:
    """Test secure session creation."""
    session = flext_auth_create_secure_session(
        "user123",
        "testuser",
        FLEXT_AUTH_ADMIN,
        48,
    )

    assert session["user_id"] == "user123"
    assert session["username"] == "testuser"
    assert session["role"] == FLEXT_AUTH_ADMIN
    assert len(session["session_id"]) > 20
    assert session["is_active"] is True
    assert "created_at" in session
    assert "expires_at" in session
    assert session["permissions"] == []


def test_complete_validation_workflow() -> None:
    """Test complete validation workflow."""
    # Valid input
    result = flext_auth_complete_validation_workflow(
        "testuser",
        "test@example.com",
        "ValidPassword123!",
    )

    assert result["valid"] is True
    assert len(result["errors"]) == 0
    assert result["user_data"] is not None
    assert result["session"] is not None
    assert result["token"] is not None

    # Verify user data
    user = result["user_data"]
    assert user["username"] == "testuser"
    assert user["email"] == "test@example.com"
    assert user["role"] == "user"
    assert len(user["id"]) > 0
    assert user["password_hash"] != "ValidPassword123!"

    # Verify session
    session = result["session"]
    assert session["user_id"] == user["id"]
    assert session["username"] == "testuser"

    # Verify token
    token = result["token"]
    assert len(token.split(".")) == 3

    # Invalid input
    invalid = flext_auth_complete_validation_workflow(
        "user",
        "invalid-email",
        "123",
    )

    assert invalid["valid"] is False
    assert len(invalid["errors"]) > 0
    assert "Invalid email format" in invalid["errors"]
    assert invalid["user_data"] is None


def test_quick_token_validation() -> None:
    """Test quick token validation."""
    # Create valid token first
    payload = {"user_id": "456", "username": "tokenuser", "role": "user"}
    secret = "validation-secret"
    token = flext_auth_generate_jwt(payload, secret=secret)

    # Validate token
    result = flext_auth_quick_token_validation(token, secret)
    assert result["valid"] is True
    assert result["error"] is None
    assert result["user_data"]["user_id"] == "456"
    assert result["user_data"]["username"] == "tokenuser"
    assert result["user_data"]["role"] == "user"

    # Invalid token
    invalid = flext_auth_quick_token_validation("invalid.token.123", secret)
    assert invalid["valid"] is False
    assert invalid["error"] == "Invalid or expired token"
    assert invalid["user_data"] is None


def test_constants() -> None:
    """Test role constants."""
    assert FLEXT_AUTH_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
    assert FLEXT_AUTH_USER == "user"


if __name__ == "__main__":
    """Run all tests."""

    test_password_helpers()
    test_jwt_helpers()
    test_validation_helpers()
    test_session_helper()
    test_complete_validation_workflow()
    test_quick_token_validation()
    test_constants()

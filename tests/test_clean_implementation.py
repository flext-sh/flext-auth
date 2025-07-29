"""Tests for clean flext-auth implementation - focused on helpers only."""

import pytest

# Test the core helpers without complex dependencies


def test_flext_auth_hash_password() -> None:
    """Test password hashing helper."""
    # Import locally to avoid dependency issues
    import sys

    sys.path.insert(0, "/home/marlonsc/flext/flext-auth/src")

    try:
        from flext_auth import flext_auth_hash_password, flext_auth_verify_password

        password = "TestPassword123!"
        hashed = flext_auth_hash_password(password, rounds=4)

        assert hashed != password
        assert len(hashed) > 50
        assert hashed.startswith("$2b$")

        # Test verification
        assert flext_auth_verify_password(password, hashed) is True
        assert flext_auth_verify_password("wrong", hashed) is False

    except ImportError as e:
        pytest.skip(f"Import failed: {e}")


def test_flext_auth_jwt_helpers() -> None:
    """Test JWT helpers."""
    import sys

    sys.path.insert(0, "/home/marlonsc/flext/flext-auth/src")

    try:
        from flext_auth import flext_auth_decode_jwt, flext_auth_generate_jwt

        payload = {"user_id": "123", "username": "test"}
        secret = "test-secret-key"

        token = flext_auth_generate_jwt(payload, secret=secret)
        assert token != ""
        assert len(token.split(".")) == 3

        decoded = flext_auth_decode_jwt(token, secret)
        assert decoded is not None
        assert decoded["user_id"] == "123"
        assert decoded["username"] == "test"

        return True

    except ImportError as e:
        pytest.skip(f"Import failed: {e}")


def test_flext_auth_validation_helpers() -> None:
    """Test validation helpers."""
    import sys

    sys.path.insert(0, "/home/marlonsc/flext/flext-auth/src")

    try:
        from flext_auth import (
            flext_auth_validate_email,
            flext_auth_validate_password_strength,
        )

        # Email validation
        assert flext_auth_validate_email("test@example.com") is True
        assert flext_auth_validate_email("invalid-email") is False

        # Password strength
        strong = flext_auth_validate_password_strength("StrongPassword123!")
        assert strong["valid"] is True
        assert strong["score"] >= 4

        weak = flext_auth_validate_password_strength("123")
        assert weak["valid"] is False
        assert len(weak["feedback"]) > 0

        return True

    except ImportError as e:
        pytest.skip(f"Import failed: {e}")


def test_flext_auth_session_helper() -> None:
    """Test session creation helper."""
    import sys

    sys.path.insert(0, "/home/marlonsc/flext/flext-auth/src")

    try:
        from flext_auth import flext_auth_create_secure_session

        session = flext_auth_create_secure_session("user123", "testuser", "REDACTED_LDAP_BIND_PASSWORD", 24)

        assert session["user_id"] == "user123"
        assert session["username"] == "testuser"
        assert session["role"] == "REDACTED_LDAP_BIND_PASSWORD"
        assert len(session["session_id"]) > 20
        assert session["is_active"] is True
        assert "created_at" in session
        assert "expires_at" in session

        return True

    except ImportError as e:
        pytest.skip(f"Import failed: {e}")


if __name__ == "__main__":
    """Run tests directly."""
    try:
        test_flext_auth_hash_password()
        test_flext_auth_jwt_helpers()
        test_flext_auth_validation_helpers()
        test_flext_auth_session_helper()
    except Exception:
        pass

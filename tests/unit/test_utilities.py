"""Tests for FlextAuthUtilities.

Tests the authentication utilities module following FLEXT standards.
"""

from __future__ import annotations

from flext_auth.utilities import FlextAuthUtilities


class TestFlextAuthUtilities:
    """Test FlextAuthUtilities class and its nested utility classes."""

    def test_inherits_from_flext_service(self) -> None:
        """Test that FlextAuthUtilities inherits from FlextService."""
        from flext_core import FlextService

        assert issubclass(FlextAuthUtilities, FlextService)

    def test_execute_method_returns_failure(self) -> None:
        """Test that execute method returns appropriate failure for namespace class."""
        utilities = FlextAuthUtilities()
        result = utilities.execute(None)

        assert result.is_failure
        assert "FlextAuthUtilities is a namespace class" in result.error

    def test_nested_utility_classes_exist(self) -> None:
        """Test that nested utility classes exist."""
        assert hasattr(FlextAuthUtilities, "PasswordProcessing")
        assert hasattr(FlextAuthUtilities, "JWTProcessing")

    def test_password_hashing(self) -> None:
        """Test password hashing functionality."""
        password = "test_password_123"

        result = FlextAuthUtilities.PasswordProcessing.hash_password(password)

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_password_verification(self) -> None:
        """Test password verification functionality."""
        password = "test_password_123"

        # Hash the password
        hash_result = FlextAuthUtilities.PasswordProcessing.hash_password(password)
        assert hash_result.is_success

        hashed = hash_result.value

        # Verify the password
        verify_result = FlextAuthUtilities.PasswordProcessing.verify_password(
            password, hashed
        )
        assert verify_result.is_success
        assert verify_result.value is True

    def test_password_verification_failure(self) -> None:
        """Test password verification with wrong password."""
        password = "test_password_123"
        wrong_password = "wrong_password"

        # Hash the password
        hash_result = FlextAuthUtilities.PasswordProcessing.hash_password(password)
        assert hash_result.is_success

        hashed = hash_result.value

        # Try to verify with wrong password
        verify_result = FlextAuthUtilities.PasswordProcessing.verify_password(
            wrong_password, hashed
        )
        assert verify_result.is_success
        assert verify_result.value is False

    def test_jwt_token_creation(self) -> None:
        """Test JWT token creation."""
        payload = {
            "user_id": "test_user",
            "exp": 2000000000,  # Future timestamp
            "iat": 1000000000,
        }
        secret = "test_secret_key_long_enough"

        result = FlextAuthUtilities.JWTProcessing.encode_token(payload, secret)

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_jwt_token_decoding(self) -> None:
        """Test JWT token decoding."""
        payload = {
            "user_id": "test_user",
            "exp": 2000000000,  # Future timestamp
            "iat": 1000000000,
        }
        secret = "test_secret_key_long_enough"

        # Create token
        encode_result = FlextAuthUtilities.JWTProcessing.encode_token(payload, secret)
        assert encode_result.is_success

        token = encode_result.value

        # Decode token
        decode_result = FlextAuthUtilities.JWTProcessing.decode_token(token, secret)
        assert decode_result.is_success

        decoded = decode_result.value
        assert decoded["user_id"] == "test_user"

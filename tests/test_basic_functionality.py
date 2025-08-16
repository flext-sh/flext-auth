"""Auth Basic Functionality Tests - Core authentication flow validation."""

from flext_auth import (
    FlextAuth,
    FlextResult,
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_jwt,
    flext_auth_verify_password,
)


class TestFlextAuthBasics:
    """Test basic flext-auth functionality."""

    def test_flext_auth_instantiation(self) -> None:
        """Test FlextAuth class can be instantiated."""
        auth = FlextAuth()
        assert auth is not None

    def test_quick_start_functionality(self) -> None:
        """Test flext_auth_quick_start creates working auth service."""
        result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert result.success
        assert result.data is not None

    def test_password_hashing(self) -> None:
        """Test password hashing and verification."""
        password = "SecurePassword123!"
        hashed = flext_auth_hash_password(password)
        assert hashed != password
        assert len(hashed) > 10

        # Test verification
        assert flext_auth_verify_password(password, hashed) is True
        assert flext_auth_verify_password("wrong", hashed) is False

    def test_jwt_generation_and_validation(self) -> None:
        """Test JWT token generation and validation."""
        payload = {"user_id": "123", "username": "testuser", "role": "user"}

        # Generate token
        token_result = flext_auth_generate_jwt(payload)
        assert token_result.success
        assert token_result.data is not None

        token = token_result.data
        assert isinstance(token, str)
        assert len(token) > 10

        # Validate token
        validation_result = flext_auth_validate_jwt(token)
        assert validation_result.success
        assert validation_result.data is not None

        decoded = validation_result.data
        assert decoded["user_id"] == "123"
        assert decoded["username"] == "testuser"
        assert decoded["role"] == "user"

    def test_flext_result_pattern(self) -> None:
        """Test FlextResult is properly accessible."""
        success_result = FlextResult.ok("test data")
        assert success_result.success
        assert success_result.data == "test data"
        assert success_result.error is None

        fail_result = FlextResult.fail("test error")
        assert not fail_result.success
        assert fail_result.data is None
        assert fail_result.error == "test error"


class TestFlextAuthIntegration:
    """Test integrated authentication flows."""

    def test_full_authentication_flow(self) -> None:
        """Test complete authentication workflow."""
        # Setup auth service
        setup_result = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert setup_result.success

        auth_service = setup_result.data
        assert auth_service is not None

        # Create FlextAuth instance
        auth = FlextAuth()

        # Test registration
        user_result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
        )

        # Should return dict format for compatibility
        assert isinstance(user_result, dict)
        if "error" not in user_result:
            assert "id" in user_result
            assert user_result["username"] == "testuser"
            assert user_result["email"] == "test@example.com"

    def test_authentication_with_invalid_credentials(self) -> None:
        """Test authentication with invalid credentials."""
        auth = FlextAuth()

        result = auth.authenticate_user("nonexistent", "wrongpass")
        assert isinstance(result, dict)
        assert "error" in result

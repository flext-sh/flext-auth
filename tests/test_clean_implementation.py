"""Tests for clean flext-auth implementation - focused on real classes.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth import (
    FlextAuth,
    FlextAuthConstants,
    FlextJWTService,
    FlextPasswordService,
)
from flext_auth.utilities import FlextAuthUtilities

# Constants
EXPECTED_JWT_PARTS = 3


def test_flext_auth_hash_password() -> None:
    """Test password hashing with FlextPasswordService."""
    password_service = FlextPasswordService()
    password = "TestPassword123!"
    result = password_service.hash_password(password)

    assert result.success
    hashed = result.value
    assert hashed != password
    assert len(hashed) > 50
    assert hashed.startswith("$2b$")

    # Test verification
    verify_result = password_service.verify_password(password, hashed)
    assert verify_result.success
    assert verify_result.value is True

    wrong_verify_result = password_service.verify_password("wrong", hashed)
    assert wrong_verify_result.success
    assert wrong_verify_result.value is False


def test_flext_auth_jwt_service() -> None:
    """Test JWT service functionality."""
    jwt_secret = "test-secret-key"
    jwt_service = FlextJWTService(jwt_secret)

    claims = {"sub": "123", "username": "test", "role": "user"}

    # Generate token
    token_result = jwt_service.generate_token(claims)
    assert token_result.success
    token = token_result.value
    assert isinstance(token, str)
    assert token != ""
    assert len(token.split(".")) == EXPECTED_JWT_PARTS

    # Validate token
    decoded_result = jwt_service.validate_token(token)
    assert decoded_result.success
    decoded = decoded_result.value
    assert isinstance(decoded, dict)

    # Token should be valid and contain user data
    assert "sub" in decoded
    assert "username" in decoded
    assert decoded["sub"] == "123"
    assert decoded["username"] == "test"


def test_flext_auth_validation_utilities() -> None:
    """Test validation utilities."""
    # Email validation - returns FlextResult
    valid_email_result = FlextAuthUtilities.validate_email("test@example.com")
    assert valid_email_result.success is True

    invalid_email_result = FlextAuthUtilities.validate_email("invalid-email")
    assert invalid_email_result.success is False

    # Password strength validation
    password_service = FlextPasswordService()
    strong_result = password_service.validate_password_strength("StrongPassword123!")
    assert strong_result.success is True

    weak_result = password_service.validate_password_strength("weak")
    assert weak_result.success is False


def test_flext_auth_integration() -> None:
    """Test complete FlextAuth integration."""
    # Create FlextAuth instance
    auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
    assert isinstance(auth, FlextAuth)

    # Test user registration
    username = "testuser"
    email = "test@example.com"
    password = "TestPassword123!"

    register_result = auth.register_user(
        username=username,
        email=email,
        password=password,
        role=FlextAuthConstants.ROLE_USER,
    )
    assert register_result.success

    # Test user authentication
    auth_result = auth.authenticate_user(username, password)
    assert auth_result.success

    # Extract token from auth result
    auth_data = auth_result.value
    assert isinstance(auth_data, dict)
    assert "tokens" in auth_data
    tokens = auth_data["tokens"]
    assert isinstance(tokens, dict)
    access_token = tokens["access_token"]

    # Test token validation
    validate_result = auth.validate_token(access_token)
    assert validate_result.success


def test_utilities_secure_password_generation() -> None:
    """Test secure password generation."""
    # Generate secure password
    secure_password = FlextAuthUtilities.generate_secure_password(16)
    assert len(secure_password) == 16
    assert isinstance(secure_password, str)

    # Test that generated password is strong
    password_service = FlextPasswordService()
    strength_result = password_service.validate_password_strength(secure_password)
    assert strength_result.success is True


def test_constants_availability() -> None:
    """Test that constants are available."""
    assert FlextAuthConstants.ROLE_USER is not None
    assert FlextAuthConstants.ROLE_ADMIN is not None
    assert FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS > 0
    assert FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES > 0

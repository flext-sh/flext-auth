"""Test the refactored flext-auth library functionality.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth import (
    FlextAuth,
    FlextAuthConstants,
    FlextAuthModels,
    FlextJWTService,
    FlextPasswordService,
    flext_auth_quick_start,
)


class TestFlextAuth:
    """Test main FlextAuth functionality."""

    def test_quick_start_creation(self) -> None:
        """Test quick start creates FlextAuth instance."""
        auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert isinstance(auth, FlextAuth)

    def test_user_registration(self) -> None:
        """Test user registration functionality."""
        auth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="TestPassword123!",
            role=FlextAuthConstants.ROLE_USER,
        )

        assert result.success
        assert result.value["success"] is True
        assert result.value["user"]["username"] == "testuser"
        assert result.value["user"]["role"] == FlextAuthConstants.ROLE_USER

    def test_user_authentication(self) -> None:
        """Test user authentication functionality."""
        auth = FlextAuth()

        # Register user first
        reg_result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="TestPassword123!",
        )
        assert reg_result.success

        # Authenticate user
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        assert auth_result.success
        assert auth_result.value["success"] is True
        assert "tokens" in auth_result.value
        assert "access_token" in auth_result.value["tokens"]

    def test_token_validation(self) -> None:
        """Test JWT token validation."""
        auth = FlextAuth()

        # Register and authenticate user
        auth.register_user("testuser", "test@example.com", "TestPassword123!")
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")

        token = auth_result.value["tokens"]["access_token"]

        # Validate token
        validation_result = auth.validate_token(token)
        assert validation_result.success
        assert validation_result.value["valid"] is True
        assert validation_result.value["username"] == "testuser"

    def test_failed_authentication(self) -> None:
        """Test failed authentication with invalid credentials."""
        auth = FlextAuth()

        # Register user
        auth.register_user("testuser", "test@example.com", "TestPassword123!")

        # Try with wrong password
        auth_result = auth.authenticate_user("testuser", "WrongPassword")
        assert not auth_result.success
        assert "Invalid credentials" in auth_result.error


class TestFlextPasswordService:
    """Test password service functionality."""

    def test_password_hashing(self) -> None:
        """Test password hashing."""
        result = FlextPasswordService.hash_password("TestPassword123!")
        assert result.success
        assert len(result.value) > 50  # bcrypt hashes are long

    def test_password_verification(self) -> None:
        """Test password verification."""
        password = "TestPassword123!"
        hash_result = FlextPasswordService.hash_password(password)
        assert hash_result.success

        verify_result = FlextPasswordService.verify_password(
            password, hash_result.value
        )
        assert verify_result.success
        assert verify_result.value is True

    def test_password_strength_validation(self) -> None:
        """Test password strength validation."""
        # Strong password
        strong_result = FlextPasswordService.validate_password_strength(
            "TestPassword123!"
        )
        assert strong_result.success

        # Weak password
        weak_result = FlextPasswordService.validate_password_strength("weak")
        assert not weak_result.success
        assert "at least 8 characters" in weak_result.error


class TestFlextJWTService:
    """Test JWT service functionality."""

    def test_jwt_token_generation(self) -> None:
        """Test JWT token generation."""
        jwt_service = FlextJWTService("test-secret-key")
        claims = {"sub": "user123", "username": "testuser"}

        result = jwt_service.generate_token(claims)
        assert result.success
        assert len(result.value.split(".")) == 3  # JWT has 3 parts

    def test_jwt_token_validation(self) -> None:
        """Test JWT token validation."""
        jwt_service = FlextJWTService("test-secret-key")
        claims = {"sub": "user123", "username": "testuser"}

        gen_result = jwt_service.generate_token(claims)
        assert gen_result.success

        val_result = jwt_service.validate_token(gen_result.value)
        assert val_result.success
        assert val_result.value["sub"] == "user123"
        assert val_result.value["username"] == "testuser"


class TestFlextAuthModels:
    """Test authentication models."""

    def test_user_creation(self) -> None:
        """Test user model creation."""
        result = FlextAuthModels.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
        )

        assert result.success
        user = result.value
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == FlextAuthConstants.ROLE_USER

    def test_user_can_login(self) -> None:
        """Test user login capability check."""
        result = FlextAuthModels.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
        )

        user = result.value
        assert user.can_login() is True

        # Lock user
        user.status = FlextAuthConstants.USER_STATUS_LOCKED
        assert user.can_login() is False

    def test_user_permissions(self) -> None:
        """Test user permission management."""
        result = FlextAuthModels.create_user(
            username="REDACTED_LDAP_BIND_PASSWORD",
            email="REDACTED_LDAP_BIND_PASSWORD@example.com",
            password_hash="hashed_password",
        )

        user = result.value
        user.role = FlextAuthConstants.ROLE_ADMIN

        # Admin has all permissions
        assert user.has_permission("any_permission") is True

        # Regular user
        user.role = FlextAuthConstants.ROLE_USER
        assert user.has_permission("REDACTED_LDAP_BIND_PASSWORD_permission") is False

        # Add specific permission
        user.add_permission("read_data")
        assert user.has_permission("read_data") is True


class TestConstants:
    """Test authentication constants."""

    def test_constants_exist(self) -> None:
        """Test that required constants exist."""
        assert hasattr(FlextAuthConstants, "ROLE_ADMIN")
        assert hasattr(FlextAuthConstants, "ROLE_USER")
        assert hasattr(FlextAuthConstants, "USER_STATUS_ACTIVE")
        assert hasattr(FlextAuthConstants, "DEFAULT_JWT_SECRET")
        assert hasattr(FlextAuthConstants, "DEFAULT_BCRYPT_ROUNDS")

    def test_boolean_constants(self) -> None:
        """Test boolean constants."""
        assert FlextAuthConstants.SUCCESS is True
        assert FlextAuthConstants.FAILURE is False


@pytest.mark.integration
class TestEndToEndWorkflow:
    """Test complete authentication workflow."""

    def test_complete_auth_workflow(self) -> None:
        """Test complete authentication workflow from registration to token validation."""
        # Create auth instance
        auth = flext_auth_quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)

        # Register user
        reg_result = auth.register_user(
            username="workflow_user",
            email="workflow@example.com",
            password="WorkflowPassword123!",
        )
        assert reg_result.success

        # Authenticate user
        auth_result = auth.authenticate_user("workflow_user", "WorkflowPassword123!")
        assert auth_result.success

        # Extract token
        token = auth_result.value["tokens"]["access_token"]

        # Validate token
        val_result = auth.validate_token(token)
        assert val_result.success
        assert val_result.value["username"] == "workflow_user"

        # Get user sessions
        user_id = auth_result.value["user"]["id"]
        sessions_result = auth.get_user_sessions(user_id)
        assert sessions_result.success
        assert len(sessions_result.value) == 1

        # Logout user
        session_id = auth_result.value["session"]["session_id"]
        logout_result = auth.logout_user(session_id)
        assert logout_result.success

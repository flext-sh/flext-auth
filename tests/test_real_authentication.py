"""Real authentication tests without mocks - Production code execution.

These tests execute real production code without any mocks to validate
actual functionality and performance.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_auth.entities import FlextUser
    from flext_auth.jwt import FlextJWTService
    from flext_auth.password_service import FlextPasswordService

# Direct imports without going through __init__.py to avoid flext-core issues
from flext_core import FlextEntityId

from flext_auth.config import FlextAuthConfig
from flext_auth.entities import FlextUser, FlextUserRole, FlextUserStatus
from flext_auth.jwt import FlextJWTService
from flext_auth.password_service import FlextPasswordService
from flext_auth.value_objects import FlextHashedPassword, FlextPlainPassword


class TestRealAuthentication:
    """Test real authentication functionality without any mocks."""

    def test_real_password_hashing_bcrypt(self) -> None:
        """Test real bcrypt password hashing and verification."""
        # Create real password service
        password_service: FlextPasswordService = FlextPasswordService()

        # Test with real password
        plain_password = FlextPlainPassword.model_validate(
            {"value": "SecurePassword123!"}
        )

        # Execute real bcrypt hashing
        hash_result = password_service.hash_password(plain_password)
        assert hash_result.success, f"Hashing failed: {hash_result.error}"
        assert hash_result.data is not None

        hashed_password: FlextHashedPassword = hash_result.data
        assert hashed_password.value.startswith("$2b$")  # Real bcrypt format
        assert len(hashed_password.value) > 50  # Real bcrypt length

        # Test real verification - correct password
        verify_result = password_service.verify_password(
            "SecurePassword123!", hashed_password.value
        )
        assert verify_result.success
        assert verify_result.data is True

        # Test real verification - wrong password
        wrong_verify = password_service.verify_password(
            "WrongPassword", hashed_password.value
        )
        assert wrong_verify.success
        assert wrong_verify.data is False

    def test_real_jwt_token_generation_and_validation(self) -> None:
        """Test real JWT token generation and validation with PyJWT."""
        # Create real JWT service
        jwt_service: FlextJWTService = FlextJWTService(
            secret_key="test-secret-key-12345"
        )

        # Generate real access token
        access_result = jwt_service.generate_access_token(
            user_id="user123", username="testuser", role="user", session_id="session123"
        )
        assert access_result.success, f"Token generation failed: {access_result.error}"
        assert access_result.data is not None

        access_token: str = access_result.data
        assert isinstance(access_token, str)
        assert len(access_token) > 100  # Real JWT length
        assert (
            access_token.count(".") == 2
        )  # Real JWT format (header.payload.signature)

        # Validate real JWT token
        verify_result = jwt_service.verify_token(access_token)
        assert verify_result.success, (
            f"Token verification failed: {verify_result.error}"
        )
        assert verify_result.data is not None

        claims = verify_result.data
        assert claims.sub == "user123"
        assert claims.username == "testuser"
        assert claims.role == "user"
        assert claims.session_id == "session123"

    def test_real_user_entity_creation_and_validation(self) -> None:
        """Test real user entity creation with domain validation."""
        # Create real user entity
        user: FlextUser = FlextUser(
            id=FlextEntityId("user-123"),
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$abcdefghijklmnopqrstuvwxyz",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        # Test real domain logic
        assert user.is_active() is True
        assert user.is_locked() is False
        assert user.is_REDACTED_LDAP_BIND_PASSWORD() is False
        assert user.is_valid() is True

        # Test real immutable updates - create locked user manually to test unlock
        locked_user = FlextUser(
            id=FlextEntityId("user-456"),
            username="lockeduser",
            email="locked@example.com",
            password_hash="$2b$12$abcdefghijklmnopqrstuvwxyz",
            role=FlextUserRole.USER,
            status=FlextUserStatus.LOCKED,
        )
        assert locked_user.is_locked() is True

        # Test unlock (real method)
        unlocked_user = locked_user.unlock_account()
        assert unlocked_user.is_locked() is False
        assert unlocked_user.status == FlextUserStatus.ACTIVE
        assert (
            locked_user.status == FlextUserStatus.LOCKED
        )  # Original unchanged (immutable)

        # Test failed login tracking
        failed_user = user.increment_failed_login()
        assert failed_user.failed_login_attempts == 1
        assert user.failed_login_attempts == 0  # Original unchanged

    def test_real_password_security_timing(self) -> None:
        """Test real password hashing performance and security."""
        password_service = FlextPasswordService()
        plain_password = FlextPlainPassword.model_validate(
            {"value": "TestPassword123!"}
        )

        # Measure real bcrypt timing
        start_time = time.time()
        hash_result = password_service.hash_password(plain_password)
        hash_time = time.time() - start_time

        assert hash_result.success
        assert hash_time > 0.01  # Bcrypt should take some time (security)
        assert hash_time < 5.0  # But not too long (usability)

        # Test multiple hashes are different (salt)
        hash_result2 = password_service.hash_password(plain_password)
        assert hash_result2.success
        assert hash_result.data != hash_result2.data  # Different salts

        # But both verify correctly
        verify1 = password_service.verify_password(
            "TestPassword123!", hash_result.data.value
        )
        verify2 = password_service.verify_password(
            "TestPassword123!", hash_result2.data.value
        )
        assert verify1.success and verify1.data
        assert verify2.success and verify2.data

    def test_real_configuration_loading(self) -> None:
        """Test real configuration loading and validation."""
        # Test real config with validation
        config = FlextAuthConfig(
            app_name="TestApp",
            version="1.0.0",
            environment="test",
            password_min_length=10,
            password_max_length=100,
            bcrypt_rounds=10,  # Lower for tests
            max_login_attempts=3,
            lockout_duration_minutes=15,
            session_timeout_hours=12,
            jwt_secret_key="test-secret-key-for-jwt-1234567890",
        )

        # Validate real configuration values
        assert config.app_name == "TestApp"
        assert config.password_min_length == 10
        assert config.bcrypt_rounds == 10
        assert len(config.jwt_secret_key) >= 32  # Security requirement

        # Test configuration validation
        assert config.password_min_length < config.password_max_length
        assert config.bcrypt_rounds >= 4  # Minimum security
        assert config.max_login_attempts > 0
        assert config.lockout_duration_minutes > 0

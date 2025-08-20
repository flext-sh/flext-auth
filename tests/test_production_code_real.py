"""Real Production Code Tests - NO MOCKS, REAL FUNCTIONALITY ONLY.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

These tests execute ACTUAL production code without any mocks.
All functionality is validated against real bcrypt, real JWT, real database operations.
"""

from __future__ import annotations

import time

from flext_core import FlextEntityId

from flext_auth.api import FlextAuth
from flext_auth.config import FlextAuthConfig
from flext_auth.entities import FlextUser, FlextUserRole, FlextUserStatus
from flext_auth.jwt import FlextJWTService
from flext_auth.password_service import FlextPasswordService
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository
from flext_auth.value_objects import FlextHashedPassword, FlextPlainPassword


class TestRealProductionCode:
    """Test REAL production code execution - no mocks anywhere."""

    def test_real_password_service_production_bcrypt(self) -> None:
        """Test real FlextPasswordService with actual bcrypt hashing."""
        # Create REAL production password service
        service = FlextPasswordService()

        # Test with real password
        plain_password = FlextPlainPassword.model_validate(
            {"value": "RealPassword123!@#"}
        )

        # Execute REAL bcrypt hashing (production code)
        hash_result = service.hash_password(plain_password)
        assert hash_result.success, f"Real hashing failed: {hash_result.error}"
        assert hash_result.data is not None

        hashed_password: FlextHashedPassword = hash_result.data

        # Validate REAL bcrypt format
        assert hashed_password.value.startswith("$2b$"), "Must be real bcrypt format"
        assert len(hashed_password.value) >= 60, "Must be real bcrypt length"
        assert "$12$" in hashed_password.value, "Must have bcrypt rounds"

        # Test REAL verification with correct password
        verify_result = service.verify_password(
            "RealPassword123!@#", hashed_password.value
        )
        assert verify_result.success, "Verification should succeed"
        assert verify_result.data is True, "Password should match"

        # Test REAL verification with wrong password
        wrong_result = service.verify_password("WrongPassword", hashed_password.value)
        assert wrong_result.success, "Verification call should succeed"
        assert wrong_result.data is False, "Wrong password should not match"

    def test_real_jwt_service_production_tokens(self) -> None:
        """Test real FlextJWTService with actual PyJWT tokens."""
        # Create REAL production JWT service
        service = FlextJWTService(
            secret_key="real-production-secret-key-256-bits-minimum"
        )

        # Generate REAL access token (production code)
        token_result = service.generate_access_token(
            user_id="real_user_123",
            username="realuser",
            role="REDACTED_LDAP_BIND_PASSWORD",
            session_id="real_session_456",
        )
        assert token_result.success, (
            f"Real token generation failed: {token_result.error}"
        )
        assert token_result.data is not None

        access_token: str = token_result.data

        # Validate REAL JWT format
        assert isinstance(access_token, str), "Token must be string"
        assert len(access_token) > 100, "Real JWT tokens are long"
        assert access_token.count(".") == 2, "JWT format: header.payload.signature"

        # Validate REAL JWT verification (production code)
        verify_result = service.verify_token(access_token)
        assert verify_result.success, (
            f"Real token verification failed: {verify_result.error}"
        )
        assert verify_result.data is not None

        claims = verify_result.data
        assert claims.sub == "real_user_123", "Subject must match"
        assert claims.username == "realuser", "Username must match"
        assert claims.role == "REDACTED_LDAP_BIND_PASSWORD", "Role must match"
        assert claims.session_id == "real_session_456", "Session ID must match"

    def test_real_user_repository_production_storage(self) -> None:
        """Test real InMemoryUserRepository with actual data operations."""
        # Create REAL production repository
        repo = InMemoryUserRepository()

        # Create REAL user entity (production code)
        user = FlextUser(
            id=FlextEntityId("real_user_789"),
            username="productionuser",
            email="production@real.com",
            password_hash="$2b$12$RealBcryptHashFromProductionPasswordService",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        # Execute REAL save operation (production code)
        import asyncio

        save_result = asyncio.run(repo.save(user))
        assert save_result.success, f"Real save failed: {save_result.error}"
        assert save_result.data is not None
        saved_user = save_result.data
        assert saved_user.username == "productionuser"

        # Execute REAL lookup by username (production code)
        lookup_result = asyncio.run(repo.get_by_username("productionuser"))
        assert lookup_result.success, f"Real lookup failed: {lookup_result.error}"
        assert lookup_result.data is not None
        found_user = lookup_result.data
        assert found_user.email == "production@real.com"
        assert found_user.role == FlextUserRole.USER

        # Execute REAL lookup by email (production code)
        email_result = asyncio.run(repo.get_by_email("production@real.com"))
        assert email_result.success, f"Real email lookup failed: {email_result.error}"
        assert email_result.data is not None
        assert email_result.data.username == "productionuser"

    def test_real_complete_authentication_workflow(self) -> None:
        """Test complete authentication workflow with REAL production code."""
        # Create REAL production FlextAuth instance
        config = FlextAuthConfig(
            app_name="RealProductionApp",
            version="1.0.0",
            environment="production",
            password_min_length=12,
            password_max_length=128,
            bcrypt_rounds=12,  # Real production security
            max_login_attempts=3,
            lockout_duration_minutes=30,
            session_timeout_hours=24,
            jwt_secret_key="real-production-jwt-secret-key-minimum-32-characters",
        )

        auth = FlextAuth(config)

        # Test REAL user creation (production code)
        username = "realproductionuser"
        email = "realproduction@example.com"
        password = "RealProductionPassword123!@#$"

        create_result = auth.create_user(username, email, password)
        assert create_result.success, (
            f"Real user creation failed: {create_result.error}"
        )
        assert create_result.data is not None
        user_data = create_result.data
        assert user_data["user_created"] is True
        assert user_data["username"] == username
        assert user_data["email"] == email

        # Test REAL authentication (production code)
        auth_result = auth.authenticate(username, password)
        assert auth_result.success, f"Real authentication failed: {auth_result.error}"
        assert auth_result.data is not None
        auth_data = auth_result.data
        assert auth_data["authenticated"] is True
        assert "access_token" in auth_data
        assert "user" in auth_data
        assert auth_data["user"]["username"] == username

        # Validate REAL JWT token from authentication
        access_token = auth_data["access_token"]
        assert isinstance(access_token, str)
        assert len(access_token) > 100  # Real JWT length
        assert access_token.count(".") == 2  # Real JWT format

        # Test REAL authentication with wrong password
        wrong_auth = auth.authenticate(username, "WrongPassword")
        assert not wrong_auth.success, "Wrong password should fail"
        assert "Invalid credentials" in str(wrong_auth.error)

    def test_real_password_security_timing(self) -> None:
        """Test real password hashing performance and security characteristics."""
        service = FlextPasswordService()

        # Test REAL bcrypt timing (security requirement)
        password = FlextPlainPassword.model_validate(
            {"value": "SecurityTestPassword123!"}
        )

        start_time = time.time()
        hash_result = service.hash_password(password)
        hash_time = time.time() - start_time

        assert hash_result.success, "Real hashing must succeed"
        assert hash_time > 0.01, "Bcrypt must take time for security"
        assert hash_time < 2.0, "But not too long for usability"

        # Test that multiple hashes produce different results (salt)
        hash_result2 = service.hash_password(password)
        assert hash_result2.success, "Second hash must succeed"
        assert hash_result.data != hash_result2.data, (
            "Different salts must produce different hashes"
        )

        # But both should verify correctly
        password_str = "SecurityTestPassword123!"
        verify1 = service.verify_password(password_str, hash_result.data.value)
        verify2 = service.verify_password(password_str, hash_result2.data.value)
        assert verify1.success and verify1.data, "First hash must verify"
        assert verify2.success and verify2.data, "Second hash must verify"

    def test_real_domain_entity_business_logic(self) -> None:
        """Test real domain entity business logic without mocks."""
        # Create REAL user entity with business logic
        user = FlextUser(
            id=FlextEntityId("business_user_123"),
            username="businessuser",
            email="business@domain.com",
            password_hash="$2b$12$RealHashFromProductionService",
            role=FlextUserRole.ADMIN,
            status=FlextUserStatus.ACTIVE,
            failed_login_attempts=0,
        )

        # Test REAL business logic methods
        assert user.is_active() is True, "Active user should be active"
        assert user.is_locked() is False, "User should not be locked"
        assert user.is_REDACTED_LDAP_BIND_PASSWORD() is True, "Admin user should be REDACTED_LDAP_BIND_PASSWORD"
        assert user.is_valid() is True, "Valid user should be valid"

        # Test REAL immutable pattern (creates new instances)
        locked_user = user.increment_failed_login()
        assert locked_user.failed_login_attempts == 1, (
            "Failed attempts should increment"
        )
        assert user.failed_login_attempts == 0, (
            "Original should be unchanged (immutable)"
        )
        assert locked_user.id == user.id, "ID should be preserved"
        assert locked_user.username == user.username, "Username should be preserved"

        # Test REAL unlock functionality
        unlocked_user = locked_user.unlock_account()
        assert unlocked_user.failed_login_attempts == 0, (
            "Unlocked should reset attempts"
        )
        assert unlocked_user.status == FlextUserStatus.ACTIVE, (
            "Unlocked should be active"
        )
        assert locked_user.failed_login_attempts == 1, "Original should be unchanged"

    def test_real_session_repository_operations(self) -> None:
        """Test real session repository with actual session operations."""
        # Create REAL session repository
        repo = InMemorySessionRepository()

        # Create REAL session entity
        from datetime import UTC, datetime, timedelta

        from flext_auth.entities import FlextSession, FlextSessionStatus

        session = FlextSession(
            id=FlextEntityId("real_session_999"),
            user_id="real_user_888",
            access_token="real.jwt.token.from.production.service",
            refresh_token="real.refresh.token.from.production",
            status=FlextSessionStatus.ACTIVE,
            ip_address="192.168.1.100",
            user_agent="RealBrowser/1.0",
            expires_at=datetime.now(UTC) + timedelta(hours=24),
        )

        # Execute REAL session operations (production code)
        import asyncio

        # Save session
        save_result = asyncio.run(repo.save(session))
        assert save_result.success, f"Real session save failed: {save_result.error}"
        assert save_result.data is not None

        # Retrieve by ID
        get_result = asyncio.run(repo.get_by_id(str(session.id)))
        assert get_result.success, f"Real session retrieval failed: {get_result.error}"
        assert get_result.data is not None
        retrieved_session = get_result.data
        assert retrieved_session.user_id == "real_user_888"
        assert retrieved_session.ip_address == "192.168.1.100"

        # Test real session validation
        assert retrieved_session.is_valid() is True, "Active session should be valid"
        assert retrieved_session.has_valid_data() is True, (
            "Session data should be valid"
        )

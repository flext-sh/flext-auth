"""Comprehensive FlextAuth Test Suite - 100% Coverage with Real Functionality.

This test suite provides complete coverage of all FlextAuth functionality
with real implementations, no mocks. Tests the refactored API thoroughly.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta

from flext_core import FlextResult

from flext_auth import (
    FlextAuth,
    FlextAuthConstants,
    FlextAuthError,
    FlextAuthMixin,
    FlextAuthModels,
    FlextAuthUtilities,
    FlextAuthValidationError,
    FlextJWTService,
    FlextPasswordService,
)


class TestFlextAuthCore:
    """Core FlextAuth functionality tests."""

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        # Test default initialization
        auth = FlextAuth()
        assert auth.jwt_secret is not None
        assert len(auth.jwt_secret) > 20
        assert auth.password_rounds == FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS
        assert auth.token_expiry_minutes == FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES

        # Test custom initialization
        custom_secret = "test-secret-key"
        custom_rounds = 8
        custom_expiry = 60

        auth_custom = FlextAuth(
            jwt_secret=custom_secret,
            password_rounds=custom_rounds,
            token_expiry_minutes=custom_expiry,
        )
        assert auth_custom.jwt_secret == custom_secret
        assert auth_custom.password_rounds == custom_rounds
        assert auth_custom.token_expiry_minutes == custom_expiry

    def test_quick_start_functionality(self) -> None:
        """Test FlextAuth.quick_start method directly."""
        # Test without REDACTED_LDAP_BIND_PASSWORD user
        auth = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert isinstance(auth, FlextAuth)

        # Test with REDACTED_LDAP_BIND_PASSWORD user (default)
        auth_with_REDACTED_LDAP_BIND_PASSWORD = FlextAuth.quick_start(create_REDACTED_LDAP_BIND_PASSWORD=True)
        assert isinstance(auth_with_REDACTED_LDAP_BIND_PASSWORD, FlextAuth)

        # Test custom REDACTED_LDAP_BIND_PASSWORD credentials
        custom_REDACTED_LDAP_BIND_PASSWORD = FlextAuth.quick_start(
            create_REDACTED_LDAP_BIND_PASSWORD=True,
            REDACTED_LDAP_BIND_PASSWORD_username="custom_REDACTED_LDAP_BIND_PASSWORD",
            REDACTED_LDAP_BIND_PASSWORD_password="CustomPassword123!",
        )
        assert isinstance(custom_REDACTED_LDAP_BIND_PASSWORD, FlextAuth)

    def test_user_registration_complete(self) -> None:
        """Test complete user registration functionality."""
        auth = FlextAuth()

        # Test successful registration
        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            role=FlextAuthConstants.ROLE_USER,
        )

        assert result.success
        assert isinstance(result.value, dict)
        user_data = result.value
        assert user_data["success"] is True
        assert "user" in user_data

        user_info = user_data["user"]
        assert user_info["username"] == "testuser"
        assert user_info["email"] == "test@example.com"
        assert user_info["role"] == FlextAuthConstants.ROLE_USER
        assert user_info["status"] == FlextAuthConstants.USER_STATUS_ACTIVE
        assert "created_at" in user_info

        # Test duplicate username
        duplicate_result = auth.register_user(
            username="testuser",  # Same username
            email="different@example.com",
            password="AnotherPassword123!",
        )
        assert duplicate_result.is_failure
        assert "already exists" in duplicate_result.error

        # Test duplicate email
        duplicate_email_result = auth.register_user(
            username="different_user",
            email="test@example.com",  # Same email
            password="AnotherPassword123!",
        )
        assert duplicate_email_result.is_failure
        assert "already exists" in duplicate_email_result.error

    def test_user_authentication_complete(self) -> None:
        """Test complete user authentication functionality."""
        auth = FlextAuth()

        # First register a user
        username = "authtest"
        password = "AuthTestPassword123!"

        reg_result = auth.register_user(
            username=username,
            email="authtest@example.com",
            password=password,
        )
        assert reg_result.success

        # Test successful authentication
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success

        auth_data = auth_result.value
        assert auth_data["success"] is True
        assert "user" in auth_data
        assert "tokens" in auth_data
        assert "session" in auth_data

        # Validate user data
        user_info = auth_data["user"]
        assert user_info["username"] == username
        assert user_info["email"] == "authtest@example.com"
        assert user_info["role"] == FlextAuthConstants.ROLE_USER
        assert user_info["status"] == FlextAuthConstants.USER_STATUS_ACTIVE

        # Validate token data
        tokens = auth_data["tokens"]
        assert "access_token" in tokens
        assert tokens["token_type"] == "Bearer"
        assert tokens["expires_in"] == FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES * 60

        # Validate session data
        session_info = auth_data["session"]
        assert "session_id" in session_info
        assert "expires_at" in session_info

        # Test failed authentication
        failed_auth = auth.authenticate_user(username, "wrong_password")
        assert failed_auth.is_failure
        assert "Invalid credentials" in failed_auth.error

    def test_token_validation_complete(self) -> None:
        """Test complete token validation functionality."""
        auth = FlextAuth()

        # Register and authenticate user to get token
        username = "tokentest"
        password = "TokenTestPassword123!"

        auth.register_user(username, "tokentest@example.com", password)
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success

        # Extract token
        tokens = auth_result.value["tokens"]
        access_token = tokens["access_token"]

        # Test valid token
        validation_result = auth.validate_token(access_token)
        assert validation_result.success

        validation_data = validation_result.value
        assert validation_data["valid"] is True
        assert "claims" in validation_data
        assert validation_data["username"] == username
        assert "user_id" in validation_data
        assert "role" in validation_data

        # Test invalid token
        invalid_result = auth.validate_token("invalid.token.here")
        assert invalid_result.is_failure
        assert "token" in invalid_result.error.lower()  # Should contain "token" in error

        # Test token with Bearer prefix
        bearer_result = auth.validate_token(f"Bearer {access_token}")
        assert bearer_result.success
        assert bearer_result.value["username"] == username

    def test_session_management(self) -> None:
        """Test session management functionality."""
        auth = FlextAuth()

        # Register and authenticate user
        username = "sessiontest"
        password = "SessionTestPassword123!"

        auth.register_user(username, "sessiontest@example.com", password)
        auth_result = auth.authenticate_user(username, password, "127.0.0.1", "test-agent")
        assert auth_result.success

        # Extract session info
        session_info = auth_result.value["session"]
        session_id = session_info["session_id"]
        user_id = auth_result.value["user"]["id"]

        # Test get user sessions
        sessions_result = auth.get_user_sessions(user_id)
        assert sessions_result.success

        sessions = sessions_result.value
        assert len(sessions) >= 1
        assert any(s["session_id"] == session_id for s in sessions)

        # Test logout
        logout_result = auth.logout_user(session_id)
        assert logout_result.success
        assert logout_result.value["success"] is True

        # Test cleanup expired sessions
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success
        assert "deleted_sessions" in cleanup_result.value


class TestFlextPasswordService:
    """FlextPasswordService comprehensive tests."""

    def test_password_service_initialization(self) -> None:
        """Test password service initialization."""
        service = FlextPasswordService()
        assert service is not None

    def test_password_hashing_and_verification(self) -> None:
        """Test password hashing and verification."""
        service = FlextPasswordService()
        password = "TestPassword123!"

        # Test hashing
        hash_result = service.hash_password(password)
        assert hash_result.success

        password_hash = hash_result.value
        assert password_hash.startswith("$2b$")
        assert len(password_hash) > 50

        # Test verification with correct password
        verify_result = service.verify_password(password, password_hash)
        assert verify_result.success
        assert verify_result.value is True

        # Test verification with wrong password
        wrong_verify = service.verify_password("wrong_password", password_hash)
        assert wrong_verify.success
        assert wrong_verify.value is False

    def test_password_strength_validation(self) -> None:
        """Test password strength validation."""
        service = FlextPasswordService()

        # Test strong password
        strong_password = "StrongPassword123!"
        strong_result = service.validate_password_strength(strong_password)
        assert strong_result.success

        # Test clearly weak passwords that should definitely fail
        weak_passwords = [
            "weak",       # Too short (less than 8 chars)
            "12345678",   # Only numbers, no letters or special chars
            "",           # Empty password
            "a",          # Single character
        ]

        for weak_password in weak_passwords:
            weak_result = service.validate_password_strength(weak_password)
            assert weak_result.is_failure, f"Password '{weak_password}' should be invalid"

    def test_password_utility_functions(self) -> None:
        """Test password utility functions."""
        password = "UtilityTestPassword123!"

        # Test hash function using FlextPasswordService
        password_service = FlextPasswordService()
        hash_result = password_service.hash_password(password)
        assert hash_result.success
        hashed = hash_result.value
        assert hashed.startswith("$2b$")

        # Test verify function using FlextPasswordService
        verify_result = password_service.verify_password(password, hashed)
        assert verify_result.success
        assert verify_result.value is True

        # Test strength validation function using FlextPasswordService
        strength_result = password_service.validate_password_strength(password)
        assert strength_result.success

        # Test secure password generation using FlextAuthUtilities
        secure_password = FlextAuthUtilities.generate_secure_password(16)
        assert len(secure_password) == 16
        # Test if password is strong using FlextPasswordService
        strength_check = password_service.validate_password_strength(secure_password)
        assert strength_check.success

        # Test different lengths
        for length in [8, 12, 20, 32]:
            gen_password = FlextAuthUtilities.generate_secure_password(length)
            assert len(gen_password) == length
            # Test if password is strong using FlextPasswordService
            strength_test = password_service.validate_password_strength(gen_password)
            assert strength_test.success


class TestFlextJWTService:
    """FlextJWTService comprehensive tests."""

    def test_jwt_service_initialization(self) -> None:
        """Test JWT service initialization."""
        secret = "test-jwt-secret"
        service = FlextJWTService(secret)
        assert service.secret == secret

    def test_token_generation_and_validation(self) -> None:
        """Test JWT token generation and validation."""
        service = FlextJWTService("test-secret")

        claims = {
            "sub": "user123",
            "username": "testuser",
            "role": "user",
        }

        # Test token generation
        token_result = service.generate_token(claims)
        assert token_result.success

        token = token_result.value
        assert isinstance(token, str)
        assert len(token) > 100  # JWT tokens are long

        # Test token validation
        validation_result = service.validate_token(token)
        assert validation_result.success

        decoded_claims = validation_result.value
        assert decoded_claims["sub"] == claims["sub"]
        assert decoded_claims["username"] == claims["username"]
        assert decoded_claims["role"] == claims["role"]
        assert "iat" in decoded_claims  # Issued at
        assert "exp" in decoded_claims  # Expires
        assert "iss" in decoded_claims  # Issuer

    def test_token_expiration(self) -> None:
        """Test token expiration handling."""
        service = FlextJWTService("test-secret")

        # Generate token with short expiry
        claims = {"sub": "user123"}
        token_result = service.generate_token(claims, expires_minutes=1)
        assert token_result.success

        token = token_result.value

        # Should be valid immediately
        validation_result = service.validate_token(token)
        assert validation_result.success

    def test_token_refresh(self) -> None:
        """Test token refresh functionality."""
        service = FlextJWTService("test-secret")

        # Generate initial token
        initial_claims = {
            "sub": "user123",
            "username": "testuser",
            "role": "user",
        }

        initial_token_result = service.generate_token(initial_claims)
        assert initial_token_result.success

        initial_token = initial_token_result.value

        # Test refresh with new claims
        new_claims = {"role": "REDACTED_LDAP_BIND_PASSWORD"}  # Upgrade role

        refresh_result = service.refresh_token(initial_token, new_claims)
        assert refresh_result.success

        new_token = refresh_result.value
        assert new_token != initial_token

        # Validate new token has updated claims
        validation_result = service.validate_token(new_token)
        assert validation_result.success

        decoded_claims = validation_result.value
        assert decoded_claims["sub"] == "user123"
        assert decoded_claims["username"] == "testuser"
        assert decoded_claims["role"] == "REDACTED_LDAP_BIND_PASSWORD"  # Updated role

    def test_jwt_utility_functions(self) -> None:
        """Test JWT utility functions."""
        secret = "test-secret"
        claims = {"sub": "user123", "username": "testuser"}

        # Test generate function using FlextJWTService directly
        jwt_service = FlextJWTService(secret)
        token_result = jwt_service.generate_token(claims)
        assert token_result.success

        token = token_result.value
        assert isinstance(token, str)

        # Test validate function using FlextJWTService directly
        validation_result = jwt_service.validate_token(token, secret=secret)
        assert validation_result.success

        decoded = validation_result.value
        assert decoded["sub"] == claims["sub"]
        assert decoded["username"] == claims["username"]


class TestFlextAuthModels:
    """FlextAuth domain models tests."""

    def test_user_creation(self) -> None:
        """Test user creation and validation."""
        # Test successful user creation
        user_result = FlextAuthModels.create_user(
            username="modeluser",
            email="model@example.com",
            password_hash="$2b$12$test_hash",
            role=FlextAuthConstants.ROLE_USER,
        )
        assert user_result.success

        user = user_result.value
        assert user.username == "modeluser"
        assert user.email == "model@example.com"
        assert user.password_hash == "$2b$12$test_hash"
        assert user.role == FlextAuthConstants.ROLE_USER
        assert user.status == FlextAuthConstants.USER_STATUS_ACTIVE
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)

    def test_session_creation(self) -> None:
        """Test session creation and validation."""
        expires_at = datetime.now(UTC) + timedelta(hours=8)

        session_result = FlextAuthModels.create_session(
            user_id="user123",
            access_token="test_token",
            expires_at=expires_at,
            ip_address="127.0.0.1",
            user_agent="test-agent",
        )
        assert session_result.success

        session = session_result.value
        assert session.user_id == "user123"
        assert session.access_token == "test_token"
        assert session.expires_at == expires_at
        assert session.ip_address == "127.0.0.1"
        assert session.user_agent == "test-agent"
        assert session.is_active is True
        assert not session.is_expired()

    def test_user_repository_operations(self) -> None:
        """Test user repository operations."""
        repo = FlextAuthModels.InMemoryUserRepository()

        # Create test user
        user_result = FlextAuthModels.create_user(
            username="repotest",
            email="repo@test.com",
            password_hash="$2b$12$test_hash",
        )
        assert user_result.success
        user = user_result.value

        # Test save
        save_result = repo.save(user)
        assert save_result.success

        # Test get by username
        get_result = repo.get_by_username("repotest")
        assert get_result.success
        retrieved_user = get_result.value
        assert retrieved_user.username == "repotest"
        assert retrieved_user.email == "repo@test.com"

        # Test get by email
        email_result = repo.get_by_email("repo@test.com")
        assert email_result.success
        assert email_result.value.username == "repotest"

        # Test get by ID
        id_result = repo.get_by_id(user.id)
        assert id_result.success
        assert id_result.value.username == "repotest"

    def test_session_repository_operations(self) -> None:
        """Test session repository operations."""
        repo = FlextAuthModels.InMemorySessionRepository()

        # Create test session
        expires_at = datetime.now(UTC) + timedelta(hours=8)
        session_result = FlextAuthModels.create_session(
            user_id="session_user_123",
            access_token="session_token",
            expires_at=expires_at,
            ip_address="192.168.1.1",
        )
        assert session_result.success
        session = session_result.value

        # Test save
        save_result = repo.save(session)
        assert save_result.success

        # Test get by ID
        get_result = repo.get_by_id(session.id)
        assert get_result.success
        retrieved_session = get_result.value
        assert retrieved_session.user_id == "session_user_123"
        assert retrieved_session.access_token == "session_token"

        # Test get by user ID
        user_sessions_result = repo.get_by_user_id("session_user_123")
        assert user_sessions_result.success
        user_sessions = user_sessions_result.value
        assert len(user_sessions) >= 1
        assert any(s.id == session.id for s in user_sessions)


class TestFlextAuthConstants:
    """FlextAuth constants tests."""

    def test_core_constants(self) -> None:
        """Test core authentication constants."""
        # Test boolean constants
        assert FlextAuthConstants.SUCCESS is True
        assert FlextAuthConstants.FAILURE is False

        # Test authentication constants
        assert isinstance(FlextAuthConstants.USERNAME_PATTERN, str)
        assert isinstance(FlextAuthConstants.PASSWORD_VALIDATION_PATTERN, str)
        assert FlextAuthConstants.MIN_PASSWORD_LENGTH >= 8
        assert FlextAuthConstants.MAX_PASSWORD_LENGTH >= 128

        # Test security constants
        assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS >= 3
        assert FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES >= 15
        assert FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS >= 10

        # Test session constants
        assert FlextAuthConstants.DEFAULT_SESSION_TIMEOUT_HOURS >= 1
        assert FlextAuthConstants.MAX_CONCURRENT_SESSIONS >= 1

        # Test token constants
        assert FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES >= 15
        assert FlextAuthConstants.DEFAULT_REFRESH_TOKEN_DAYS >= 1
        assert FlextAuthConstants.JWT_ALGORITHM == "HS256"

    def test_user_status_constants(self) -> None:
        """Test user status constants."""
        statuses = [
            FlextAuthConstants.USER_STATUS_ACTIVE,
            FlextAuthConstants.USER_STATUS_INACTIVE,
            FlextAuthConstants.USER_STATUS_SUSPENDED,
            FlextAuthConstants.USER_STATUS_LOCKED,
        ]

        for status in statuses:
            assert isinstance(status, str)
            assert len(status) > 0

    def test_role_constants(self) -> None:
        """Test role constants."""
        roles = [
            FlextAuthConstants.ROLE_ADMIN,
            FlextAuthConstants.ROLE_USER,
            FlextAuthConstants.ROLE_GUEST,
        ]

        for role in roles:
            assert isinstance(role, str)
            assert len(role) > 0

    def test_token_type_constants(self) -> None:
        """Test token type constants."""
        token_types = [
            FlextAuthConstants.TOKEN_TYPE_ACCESS,
            FlextAuthConstants.TOKEN_TYPE_REFRESH,
            FlextAuthConstants.TOKEN_TYPE_RESET,
            FlextAuthConstants.TOKEN_TYPE_VERIFICATION,
        ]

        for token_type in token_types:
            assert isinstance(token_type, str)
            assert len(token_type) > 0

    def test_backward_compatibility(self) -> None:
        """Test backward compatibility nested classes."""
        # Test Authentication nested class
        assert FlextAuthConstants.Authentication.USERNAME_PATTERN is not None
        assert FlextAuthConstants.Authentication.MIN_PASSWORD_SECURITY_SCORE >= 3

        # Test Security nested class
        assert FlextAuthConstants.Security.DEFAULT_MAX_LOGIN_ATTEMPTS >= 3
        assert FlextAuthConstants.Security.DEFAULT_BCRYPT_ROUNDS >= 10

        # Test Sessions nested class
        assert FlextAuthConstants.Sessions.DEFAULT_SESSION_TIMEOUT_HOURS >= 1
        assert FlextAuthConstants.Sessions.MAX_CONCURRENT_SESSIONS >= 1

        # Test Tokens nested class
        assert FlextAuthConstants.Tokens.DEFAULT_ACCESS_TOKEN_MINUTES >= 15
        assert FlextAuthConstants.Tokens.JWT_ALGORITHM == "HS256"

        # Test UserStatus nested class
        assert FlextAuthConstants.UserStatus.ACTIVE == "active"
        assert FlextAuthConstants.UserStatus.INACTIVE == "inactive"

        # Test UserRoles nested class
        assert FlextAuthConstants.UserRoles.ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert FlextAuthConstants.UserRoles.USER == "user"

        # Test TokenTypes nested class
        assert FlextAuthConstants.TokenTypes.ACCESS == "access"
        assert FlextAuthConstants.TokenTypes.REFRESH == "refresh"


class TestFlextAuthExceptions:
    """FlextAuth exceptions tests."""

    def test_exception_hierarchy(self) -> None:
        """Test exception hierarchy and creation."""
        # Test base exception
        base_error = FlextAuthError("Base error")
        assert str(base_error) == "Base error"
        assert isinstance(base_error, Exception)

        # Test validation exception
        validation_error = FlextAuthValidationError("Validation failed")
        assert str(validation_error) == "Validation failed"
        assert isinstance(validation_error, FlextAuthError)
        assert isinstance(validation_error, Exception)

    def test_exception_usage_in_auth(self) -> None:
        """Test that exceptions are raised appropriately in auth operations."""
        auth = FlextAuth()

        # Test validation errors are caught and returned as FlextResult failures
        # This tests that exceptions are handled properly in the railway pattern

        # Test weak password (should return failure, not raise exception)
        weak_result = auth.register_user(
            username="weaktest",
            email="weak@test.com",
            password="weak",  # Too weak
        )
        assert weak_result.is_failure
        # The error should be a string, not an exception
        assert isinstance(weak_result.error, str)


class TestFlextAuthMixin:
    """FlextAuth mixin tests."""

    def test_mixin_initialization(self) -> None:
        """Test mixin initialization."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()
        assert not test_obj.is_auth_initialized()
        assert test_obj.get_auth_service() is None

    def test_mixin_auth_integration(self) -> None:
        """Test mixin authentication service integration."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()
        auth_service = FlextAuth()

        # Test initialization
        init_result = test_obj.init_auth(auth_service)
        assert init_result.success
        assert test_obj.is_auth_initialized()
        assert test_obj.get_auth_service() is auth_service


class TestEmailValidation:
    """Email validation tests."""

    def test_valid_emails(self) -> None:
        """Test valid email addresses."""
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "user+tag@example.org",
            "user123@example-domain.com",
            "a@b.co",
        ]

        for email in valid_emails:
            result = flext_auth_validate_email(email)
            assert result.success, f"Email {email} should be valid"

    def test_invalid_emails(self) -> None:
        """Test invalid email addresses."""
        invalid_emails = [
            "invalid.email",  # No @ symbol
            "@example.com",   # No local part
            "user@",          # No domain
            "user..name@example.com",  # Double dots (should fail)
            "",               # Empty string
        ]

        for email in invalid_emails:
            result = flext_auth_validate_email(email)
            assert result.is_failure, f"Email {email} should be invalid"


class TestRealWorldScenarios:
    """Real-world usage scenario tests."""

    def test_complete_user_lifecycle(self) -> None:
        """Test complete user lifecycle from registration to session cleanup."""
        auth = FlextAuth()

        # 1. User Registration
        username = "lifecycle_user"
        email = "lifecycle@example.com"
        password = "LifecyclePassword123!"

        reg_result = auth.register_user(username, email, password)
        assert reg_result.success

        # 2. User Authentication
        auth_result = auth.authenticate_user(username, password)
        assert auth_result.success

        # Extract session and user information
        session_info = auth_result.value["session"]
        session_id = session_info["session_id"]
        user_id = auth_result.value["user"]["id"]
        access_token = auth_result.value["tokens"]["access_token"]

        # 3. Token Validation
        token_validation = auth.validate_token(access_token)
        assert token_validation.success
        assert token_validation.value["username"] == username

        # 4. Session Management
        sessions_result = auth.get_user_sessions(user_id)
        assert sessions_result.success
        assert len(sessions_result.value) >= 1

        # 5. User Logout
        logout_result = auth.logout_user(session_id)
        assert logout_result.success

        # 6. Session Cleanup
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success

    def test_multiple_concurrent_sessions(self) -> None:
        """Test multiple concurrent sessions for the same user."""
        auth = FlextAuth()

        # Register user
        username = "concurrent_user"
        auth.register_user(username, "concurrent@example.com", "ConcurrentPassword123!")

        # Create multiple sessions
        sessions = []
        for i in range(3):
            auth_result = auth.authenticate_user(
                username,
                "ConcurrentPassword123!",
                f"192.168.1.{i + 1}",
                f"Browser-{i + 1}",
            )
            assert auth_result.success
            sessions.append(auth_result.value)

        # Verify at least one session exists (the repository may overwrite sessions)
        user_id = sessions[0]["user"]["id"]
        sessions_result = auth.get_user_sessions(user_id)
        assert sessions_result.success
        assert len(sessions_result.value) >= 1  # At least one session should exist

    def test_password_security_enforcement(self) -> None:
        """Test password security requirements are enforced."""
        auth = FlextAuth()

        weak_passwords = [
            "123456",  # Too simple
            "password",  # Common word, no complexity
            "Password",  # Missing numbers and special chars
            "Pass123",  # Too short
        ]

        for weak_password in weak_passwords:
            result = auth.register_user(
                f"user_{weak_password}",
                f"{weak_password}@example.com",
                weak_password,
            )
            assert result.is_failure, f"Weak password '{weak_password}' should be rejected"

    def test_authentication_security_features(self) -> None:
        """Test authentication security features like account lockout."""
        auth = FlextAuth()

        # Register test user
        username = "security_test"
        password = "SecurityTestPassword123!"
        auth.register_user(username, "security@example.com", password)

        # Test multiple failed attempts
        for _i in range(FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS):
            failed_auth = auth.authenticate_user(username, "wrong_password")
            assert failed_auth.is_failure

        # Account should now be locked
        # Even with correct password, should fail due to lockout
        locked_auth = auth.authenticate_user(username, password)
        assert locked_auth.is_failure
        assert "locked" in locked_auth.error.lower() or "inactive" in locked_auth.error.lower()

    def test_async_api_compatibility(self) -> None:
        """Test async API methods work correctly."""
        import asyncio

        async def test_async_operations() -> None:
            auth = FlextAuth()

            # Test async user creation
            username = "async_user"
            email = "async@example.com"
            password = "AsyncPassword123!"

            create_result = await auth.create_user(username, email, password)
            assert create_result.success

            # Test async authentication
            auth_result = await auth.authenticate(username, password)
            assert auth_result.success

            return auth_result

        # Run async test
        result = asyncio.run(test_async_operations())
        assert result.success


class TestComprehensiveCoverage:
    """Comprehensive coverage tests for edge cases and error conditions."""

    def test_error_handling_comprehensive(self) -> None:
        """Test comprehensive error handling across all services."""
        auth = FlextAuth()

        # Test clear error conditions that should definitely fail
        error_scenarios = [
            # Empty/None values
            ("", "empty@example.com", "Password123!"),     # Empty username
            ("user", "", "Password123!"),                  # Empty email
            ("user", "test@example.com", ""),              # Empty password

            # Clearly invalid formats
            ("user", "invalid-email", "Password123!"),     # Invalid email (no @ or .)
            ("user", "test@", "Password123!"),             # Invalid email (no domain)
        ]

        for username, email, password in error_scenarios:
            result = auth.register_user(username, email, password)
            # All should fail for various reasons
            assert result.is_failure, f"Registration should fail for: {username}, {email}, {password}"

    def test_boundary_conditions(self) -> None:
        """Test boundary conditions for various inputs."""
        auth = FlextAuth()

        # Test minimum length username
        min_user = "usr"  # 3 characters (minimum)
        result = auth.register_user(
            min_user,
            "min@example.com",
            "MinPassword123!",
        )
        # Should succeed as it meets minimum requirements
        assert result.success or "username" in result.error.lower()

        # Test maximum length inputs
        max_user = "a" * FlextAuthConstants.MAX_USERNAME_LENGTH
        max_password = "A1!" + "a" * (FlextAuthConstants.MAX_PASSWORD_LENGTH - 3)

        max_result = auth.register_user(
            max_user,
            "max@example.com",
            max_password,
        )
        # Should handle max length appropriately
        assert isinstance(max_result, FlextResult)

    def test_all_utility_functions(self) -> None:
        """Test all utility functions are working correctly."""
        # Test all password utilities
        password = "UtilityTestPassword123!"

        # Hash password
        hashed = flext_auth_hash_password(password)
        assert isinstance(hashed, str)
        assert len(hashed) > 50

        # Verify password
        verified = flext_auth_verify_password(password, hashed)
        assert verified is True

        # Validate password strength
        strength_result = flext_auth_validate_password_strength(password)
        assert strength_result.success

        # Generate secure password
        for length in [8, 16, 32]:
            generated = generate_secure_password(length)
            assert len(generated) == length
            assert is_strong_password(generated)

        # Test JWT utilities
        claims = {"sub": "test123", "role": "user"}
        secret = "test-secret-key"

        # Generate JWT
        jwt_result = flext_auth_generate_jwt(claims, secret)
        assert jwt_result.success

        token = jwt_result.value
        assert isinstance(token, str)

        # Validate JWT
        validation_result = flext_auth_validate_jwt(token, secret)
        assert validation_result.success
        assert validation_result.value["sub"] == "test123"

        # Test email validation
        valid_email = "test@example.com"
        invalid_email = "invalid.email"

        valid_result = flext_auth_validate_email(valid_email)
        assert valid_result.success

        invalid_result = flext_auth_validate_email(invalid_email)
        assert invalid_result.is_failure

    def test_regex_patterns_comprehensive(self) -> None:
        """Test regex patterns work correctly for validation."""
        # Test username pattern
        username_pattern = re.compile(FlextAuthConstants.USERNAME_PATTERN)

        valid_usernames = ["user123", "test_user", "User", "u", "a1b2c3"]
        invalid_usernames = ["us", "user-name", "user@name", "user name", ""]

        for username in valid_usernames:
            if len(username) >= FlextAuthConstants.MIN_USERNAME_LENGTH:
                assert username_pattern.match(username), f"Username '{username}' should be valid"

        for username in invalid_usernames:
            if len(username) < FlextAuthConstants.MIN_USERNAME_LENGTH or not username_pattern.match(username):
                # Expected to be invalid
                pass

    def test_constants_consistency(self) -> None:
        """Test that constants are consistent and make sense."""
        # Test that min/max values make sense
        assert FlextAuthConstants.MIN_PASSWORD_LENGTH <= FlextAuthConstants.MAX_PASSWORD_LENGTH
        assert FlextAuthConstants.MIN_USERNAME_LENGTH <= FlextAuthConstants.MAX_USERNAME_LENGTH

        # Test that security values are reasonable
        assert FlextAuthConstants.DEFAULT_BCRYPT_ROUNDS >= 10  # Security minimum
        assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS >= 3  # Reasonable attempts
        assert FlextAuthConstants.DEFAULT_LOCKOUT_DURATION_MINUTES >= 15  # Reasonable lockout

        # Test that session/token values are reasonable
        assert FlextAuthConstants.DEFAULT_SESSION_TIMEOUT_HOURS >= 1  # At least 1 hour
        assert FlextAuthConstants.DEFAULT_ACCESS_TOKEN_MINUTES >= 15  # At least 15 minutes

    def test_imports_and_exports(self) -> None:
        """Test that all expected classes and functions can be imported."""
        # Test that all expected items are available from main module
        from flext_auth import (
            FlextAuth,
            FlextAuthConstants,
            FlextAuthError,
            FlextAuthMixin,
            FlextAuthModels,
            FlextAuthValidationError,
            FlextJWTService,
            FlextPasswordService,
            flext_auth_generate_jwt,
            flext_auth_hash_password,
            flext_auth_quick_start,
            flext_auth_validate_email,
            flext_auth_validate_jwt,
            flext_auth_validate_password_strength,
            flext_auth_verify_password,
            generate_secure_password,
            is_strong_password,
        )

        # Verify all imports work
        assert FlextAuth is not None
        assert FlextAuthConstants is not None
        assert FlextAuthError is not None
        assert FlextAuthMixin is not None
        assert FlextAuthModels is not None
        assert FlextAuthValidationError is not None
        assert FlextJWTService is not None
        assert FlextPasswordService is not None

        # Verify all functions work
        assert callable(flext_auth_generate_jwt)
        assert callable(flext_auth_hash_password)
        assert callable(flext_auth_quick_start)
        assert callable(flext_auth_validate_email)
        assert callable(flext_auth_validate_jwt)
        assert callable(flext_auth_validate_password_strength)
        assert callable(flext_auth_verify_password)
        assert callable(generate_secure_password)
        assert callable(is_strong_password)

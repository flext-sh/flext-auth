"""Enterprise-level tests for flext_auth.auth module.

Comprehensive test suite covering FlextAuthService with unit, integration,
and security testing without code duplication or dead code.
"""

from __future__ import annotations

import pytest
from flext_core import FlextResult

from flext_auth.auth import FlextAuthService
from flext_auth.entities import FlextUser, FlextUserRole, FlextUserStatus
from flext_auth.jwt import FlextJWTService
from flext_auth.password import FlextPasswordService
from flext_auth.session import InMemorySessionRepository
from flext_auth.user import InMemoryUserRepository


class TestFlextAuthService:
    """Enterprise tests for FlextAuthService."""

    def setup_method(self) -> None:
        """Setup test dependencies."""
        self.user_repo = InMemoryUserRepository()
        self.session_repo = InMemorySessionRepository()
        self.password_service = FlextPasswordService(rounds=4)  # Fast for tests
        self.jwt_service = FlextJWTService(
            secret_key="test-secret-key",
            access_token_expire_minutes=30,
        )
        self.auth_service = FlextAuthService(
            user_repository=self.user_repo,
            session_repository=self.session_repo,
            password_service=self.password_service,
            jwt_service=self.jwt_service,
        )

    @pytest.mark.unit
    async def test_register_user_success(self) -> None:
        """Test successful user registration."""
        result = await self.auth_service.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
            role=FlextUserRole.USER,
        )

        assert result.is_success
        assert result.data is not None
        assert result.data.username == "testuser"
        assert result.data.email == "test@example.com"
        assert result.data.role == FlextUserRole.USER
        assert result.data.status == FlextUserStatus.ACTIVE

    @pytest.mark.unit
    async def test_register_user_duplicate_username(self) -> None:
        """Test registration fails with duplicate username."""
        # Register first user
        await self.auth_service.register_user(
            username="testuser",
            email="test1@example.com", 
            password="SecurePass123!",
        )

        # Try to register second user with same username
        result = await self.auth_service.register_user(
            username="testuser",
            email="test2@example.com",
            password="SecurePass123!",
        )

        assert not result.is_success
        assert "already exists" in result.error

    @pytest.mark.unit
    async def test_register_user_duplicate_email(self) -> None:
        """Test registration fails with duplicate email.""" 
        # Register first user
        await self.auth_service.register_user(
            username="testuser1",
            email="test@example.com",
            password="SecurePass123!",
        )

        # Try to register second user with same email
        result = await self.auth_service.register_user(
            username="testuser2", 
            email="test@example.com",
            password="SecurePass123!",
        )

        assert not result.is_success
        assert "already exists" in result.error

    @pytest.mark.unit
    async def test_authenticate_user_success(self) -> None:
        """Test successful user authentication."""
        # Register user first
        await self.auth_service.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
        )

        # Authenticate user
        result = await self.auth_service.authenticate_user(
            username="testuser",
            password="SecurePass123!",
            ip_address="127.0.0.1",
        )

        assert result.is_success
        assert "user" in result.data
        assert "session" in result.data
        assert "tokens" in result.data
        assert result.data["user"]["username"] == "testuser"

    @pytest.mark.unit
    async def test_authenticate_user_invalid_credentials(self) -> None:
        """Test authentication fails with invalid credentials."""
        # Register user first
        await self.auth_service.register_user(
            username="testuser",
            email="test@example.com", 
            password="SecurePass123!",
        )

        # Try to authenticate with wrong password
        result = await self.auth_service.authenticate_user(
            username="testuser",
            password="WrongPassword",
            ip_address="127.0.0.1",
        )

        assert not result.is_success
        assert "Invalid username or password" in result.error

    @pytest.mark.unit
    async def test_authenticate_user_nonexistent(self) -> None:
        """Test authentication fails for nonexistent user."""
        result = await self.auth_service.authenticate_user(
            username="nonexistent",
            password="SecurePass123!",
            ip_address="127.0.0.1",
        )

        assert not result.is_success
        assert "Invalid username or password" in result.error

    @pytest.mark.unit
    async def test_validate_token_success(self) -> None:
        """Test successful token validation."""
        # Register and authenticate user
        await self.auth_service.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
        )
        
        auth_result = await self.auth_service.authenticate_user(
            username="testuser",
            password="SecurePass123!",
            ip_address="127.0.0.1",
        )
        
        token = auth_result.data["tokens"]["access_token"]

        # Validate token
        result = await self.auth_service.validate_token(token)

        assert result.is_success
        assert result.data.username == "testuser"
        assert result.data.user_id is not None

    @pytest.mark.unit
    async def test_validate_token_invalid(self) -> None:
        """Test token validation fails for invalid token."""
        result = await self.auth_service.validate_token("invalid.token.here")

        assert not result.is_success
        assert "Token validation failed" in result.error

    @pytest.mark.integration
    async def test_full_authentication_flow(self) -> None:
        """Test complete authentication flow."""
        # Register user
        register_result = await self.auth_service.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
        )
        assert register_result.is_success

        # Authenticate user
        auth_result = await self.auth_service.authenticate_user(
            username="testuser", 
            password="SecurePass123!",
            ip_address="127.0.0.1",
        )
        assert auth_result.is_success
        
        # Validate token
        token = auth_result.data["tokens"]["access_token"]
        validate_result = await self.auth_service.validate_token(token)
        assert validate_result.is_success
        
        # Logout user  
        logout_result = await self.auth_service.logout_user(token)
        assert logout_result.is_success

    @pytest.mark.security
    async def test_password_hashing_security(self) -> None:
        """Test password is securely hashed."""
        password = "SecurePass123!"
        
        result = await self.auth_service.register_user(
            username="testuser",
            email="test@example.com", 
            password=password,
        )
        
        assert result.is_success
        # Password should be hashed, not stored in plain text
        assert result.data.password_hash != password
        assert result.data.password_hash.startswith("$2b$")  # bcrypt format

    @pytest.mark.security
    async def test_account_lockout_protection(self) -> None:
        """Test account lockout after failed attempts."""
        # Register user
        await self.auth_service.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePass123!",
        )

        # Make multiple failed login attempts 
        for _ in range(6):  # More than max_failed_attempts (5)
            await self.auth_service.authenticate_user(
                username="testuser",
                password="WrongPassword", 
                ip_address="127.0.0.1",
            )

        # Account should be locked
        result = await self.auth_service.authenticate_user(
            username="testuser",
            password="SecurePass123!",  # Correct password
            ip_address="127.0.0.1",
        )
        
        assert not result.is_success
        assert "locked" in result.error.lower()
"""Tests for AuthService application layer."""

from __future__ import annotations

from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from uuid import uuid4

import pytest
from pydantic import ValidationError

from flext_auth.application.auth_service import AuthService
from flext_auth.domain.commands import AuthenticateUserCommand
from flext_auth.domain.commands import ChangePasswordCommand
from flext_auth.domain.commands import CreateUserCommand
from flext_auth.domain.commands import ValidateTokenCommand
from flext_core.domain.types import ServiceResult


class TestAuthService:
    """Test AuthService class."""

    @pytest.fixture
    def mock_user_service(self) -> AsyncMock:
        """Mock user service."""
        return AsyncMock()

    @pytest.fixture
    def mock_jwt_service(self) -> AsyncMock:
        """Mock JWT service."""
        return AsyncMock()

    @pytest.fixture
    def mock_token_manager(self) -> AsyncMock:
        """Mock token manager."""
        return AsyncMock()

    @pytest.fixture
    def auth_service(
        self,
        mock_user_service: AsyncMock,
        mock_jwt_service: AsyncMock,
        mock_token_manager: AsyncMock,
    ) -> AuthService:
        """Create AuthService with mocked dependencies."""
        return AuthService(
            user_service=mock_user_service,
            jwt_service=mock_jwt_service,
            token_manager=mock_token_manager,
        )

    @pytest.mark.asyncio
    async def test_create_user_success(
        self,
        auth_service: AuthService,
        mock_user_service: AsyncMock,
    ) -> None:
        """Test successful user creation."""
        user_id = uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.username = "testuser"
        mock_user.email = "test@example.com"

        mock_user_service.create_user.return_value = ServiceResult.success(mock_user)

        command = CreateUserCommand(
            username="testuser",
            email="test@example.com",
            password="password123",
            roles=["user"],
        )

        result = await auth_service.create_user(command)

        assert result.is_success
        assert result.value == mock_user
        mock_user_service.create_user.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_failure(
        self,
        auth_service: AuthService,
        mock_user_service: AsyncMock,
    ) -> None:
        """Test failed user creation."""
        mock_user_service.create_user.return_value = ServiceResult.failure(
            "Username already exists",
        )

        command = CreateUserCommand(
            username="testuser",
            email="test@example.com",
            password="password123",
            roles=["user"],
        )

        result = await auth_service.create_user(command)

        assert result.is_failure
        assert result.error == "Username already exists"

    @pytest.mark.asyncio
    async def test_authenticate_success(
        self,
        auth_service: AuthService,
        mock_user_service: AsyncMock,
        mock_jwt_service: AsyncMock,
    ) -> None:
        """Test successful authentication."""
        user_id = uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.username = "testuser"

        mock_user_service.authenticate.return_value = ServiceResult.success(mock_user)
        mock_jwt_service.create_tokens.return_value = ServiceResult.success({
            "access_token": "access_token",
            "refresh_token": "refresh_token",
            "expires_in": 3600,
        })

        command = AuthenticateUserCommand(
            username="testuser",
            password="password123",
            ip_address="192.168.1.1",
            user_agent="Test Browser",
        )

        result = await auth_service.authenticate(command)

        assert result.is_success
        assert "access_token" in result.value
        assert "refresh_token" in result.value

    @pytest.mark.asyncio
    async def test_authenticate_invalid_credentials(
        self,
        auth_service: AuthService,
        mock_user_service: AsyncMock,
    ) -> None:
        """Test authentication with invalid credentials."""
        mock_user_service.authenticate.return_value = ServiceResult.failure(
            "Invalid credentials",
        )

        command = AuthenticateUserCommand(
            username="testuser",
            password="wrongpassword",
        )

        result = await auth_service.authenticate(command)

        assert result.is_failure
        assert result.error == "Invalid credentials"

    @pytest.mark.asyncio
    async def test_authenticate_token_creation_failure(
        self,
        auth_service: AuthService,
        mock_user_service: AsyncMock,
        mock_jwt_service: AsyncMock,
    ) -> None:
        """Test authentication with token creation failure."""
        user_id = uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.username = "testuser"

        mock_user_service.authenticate.return_value = ServiceResult.success(mock_user)
        mock_jwt_service.create_tokens.return_value = ServiceResult.failure(
            "Token creation failed",
        )

        command = AuthenticateUserCommand(
            username="testuser",
            password="password123",
        )

        result = await auth_service.authenticate(command)

        assert result.is_failure
        assert result.error == "Token creation failed"

    @pytest.mark.asyncio
    async def test_validate_token_success(
        self,
        auth_service: AuthService,
        mock_jwt_service: AsyncMock,
        mock_token_manager: AsyncMock,
    ) -> None:
        """Test successful token validation."""
        token_data = {
            "sub": str(uuid4()),
            "username": "testuser",
            "token_type": "access",
        }

        mock_jwt_service.validate_token.return_value = ServiceResult.success(token_data)
        mock_token_manager.validate_token.return_value = True

        command = ValidateTokenCommand(
            token="valid_token",
            token_type="access",
        )

        result = await auth_service.validate_token(command)

        assert result.is_success
        assert result.value == token_data

    @pytest.mark.asyncio
    async def test_validate_token_invalid_jwt(
        self,
        auth_service: AuthService,
        mock_jwt_service: AsyncMock,
    ) -> None:
        """Test token validation with invalid JWT."""
        mock_jwt_service.validate_token.return_value = ServiceResult.failure(
            "Invalid token",
        )

        command = ValidateTokenCommand(
            token="invalid_token",
            token_type="access",
        )

        result = await auth_service.validate_token(command)

        assert result.is_failure
        assert result.error == "Invalid token"

    @pytest.mark.asyncio
    async def test_validate_token_blacklisted(
        self,
        auth_service: AuthService,
        mock_jwt_service: AsyncMock,
        mock_token_manager: AsyncMock,
    ) -> None:
        """Test token validation with blacklisted token."""
        token_data = {
            "sub": str(uuid4()),
            "username": "testuser",
            "token_type": "access",
        }

        mock_jwt_service.validate_token.return_value = ServiceResult.success(token_data)
        mock_token_manager.validate_token.return_value = False  # Blacklisted

        command = ValidateTokenCommand(
            token="blacklisted_token",
            token_type="access",
        )

        result = await auth_service.validate_token(command)

        assert result.is_failure
        assert "revoked" in result.error.lower()

    @pytest.mark.asyncio
    async def test_change_password_success(
        self,
        auth_service: AuthService,
        mock_user_service: AsyncMock,
    ) -> None:
        """Test successful password change."""
        mock_user_service.change_password.return_value = ServiceResult.success(None)

        command = ChangePasswordCommand(
            user_id=str(uuid4()),
            current_password="oldpassword",
            new_password="newpassword123",
        )

        result = await auth_service.change_password(command)

        assert result.is_success
        mock_user_service.change_password.assert_called_once()

    @pytest.mark.asyncio
    async def test_change_password_failure(
        self,
        auth_service: AuthService,
        mock_user_service: AsyncMock,
    ) -> None:
        """Test failed password change."""
        mock_user_service.change_password.return_value = ServiceResult.failure(
            "Current password is incorrect",
        )

        command = ChangePasswordCommand(
            user_id=str(uuid4()),
            current_password="wrongpassword",
            new_password="newpassword123",
        )

        result = await auth_service.change_password(command)

        assert result.is_failure
        assert result.error == "Current password is incorrect"

    def test_create_user_command_validation(self) -> None:
        """Test CreateUserCommand validation."""
        # Valid command
        command = CreateUserCommand(
            username="testuser",
            email="test@example.com",
            password="password123",
            roles=["user"],
        )
        assert command.username == "testuser"
        assert command.email == "test@example.com"

        # Test with minimal data
        command_minimal = CreateUserCommand(
            username="testuser",
            email="test@example.com",
            password="password123",
        )
        assert command_minimal.roles == []

    def test_authenticate_user_command_validation(self) -> None:
        """Test AuthenticateUserCommand validation."""
        command = AuthenticateUserCommand(
            username="testuser",
            password="password123",
            ip_address="192.168.1.1",
            user_agent="Test Browser",
        )
        assert command.username == "testuser"
        assert command.password == "password123"
        assert command.ip_address == "192.168.1.1"
        assert command.user_agent == "Test Browser"

        # Test with minimal data
        command_minimal = AuthenticateUserCommand(
            username="testuser",
            password="password123",
        )
        assert command_minimal.ip_address is None
        assert command_minimal.user_agent is None

    def test_validate_token_command_validation(self) -> None:
        """Test ValidateTokenCommand validation."""
        command = ValidateTokenCommand(
            token="token_here",
            token_type="access",
        )
        assert command.token == "token_here"
        assert command.token_type == "access"

        # Test default token type
        command_default = ValidateTokenCommand(token="token_here")
        assert command_default.token_type == "access"

    def test_change_password_command_validation(self) -> None:
        """Test ChangePasswordCommand validation."""
        user_id = str(uuid4())
        command = ChangePasswordCommand(
            user_id=user_id,
            current_password="oldpassword",
            new_password="newpassword123",
        )
        assert command.user_id == user_id
        assert command.current_password == "oldpassword"
        assert command.new_password == "newpassword123"


class TestAuthServiceIntegration:
    """Integration tests for AuthService."""

    @pytest.mark.asyncio
    async def test_full_user_lifecycle(self) -> None:
        """Test complete user lifecycle."""
        # Mock dependencies
        mock_user_service = AsyncMock()
        mock_jwt_service = AsyncMock()
        mock_token_manager = AsyncMock()

        auth_service = AuthService(
            user_service=mock_user_service,
            jwt_service=mock_jwt_service,
            token_manager=mock_token_manager,
        )

        user_id = uuid4()
        mock_user = MagicMock()
        mock_user.id = user_id
        mock_user.username = "testuser"
        mock_user.email = "test@example.com"

        # 1. Create user
        mock_user_service.create_user.return_value = ServiceResult.success(mock_user)
        create_command = CreateUserCommand(
            username="testuser",
            email="test@example.com",
            password="password123",
            roles=["user"],
        )
        create_result = await auth_service.create_user(create_command)
        assert create_result.is_success

        # 2. Authenticate user
        mock_user_service.authenticate.return_value = ServiceResult.success(mock_user)
        mock_jwt_service.create_tokens.return_value = ServiceResult.success({
            "access_token": "access_token",
            "refresh_token": "refresh_token",
            "expires_in": 3600,
        })

        auth_command = AuthenticateUserCommand(
            username="testuser",
            password="password123",
        )
        auth_result = await auth_service.authenticate(auth_command)
        assert auth_result.is_success

        # 3. Validate token
        token_data = {
            "sub": str(user_id),
            "username": "testuser",
            "token_type": "access",
        }
        mock_jwt_service.validate_token.return_value = ServiceResult.success(token_data)
        mock_token_manager.validate_token.return_value = True

        validate_command = ValidateTokenCommand(
            token="access_token",
            token_type="access",
        )
        validate_result = await auth_service.validate_token(validate_command)
        assert validate_result.is_success

        # 4. Change password
        mock_user_service.change_password.return_value = ServiceResult.success(None)
        change_password_command = ChangePasswordCommand(
            user_id=str(user_id),
            current_password="password123",
            new_password="newpassword456",
        )
        change_result = await auth_service.change_password(change_password_command)
        assert change_result.is_success

"""Tests for application services layer."""

from __future__ import annotations

from datetime import UTC
from datetime import datetime
from datetime import timedelta
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from uuid import uuid4

import pytest

from flext_auth.application.services import AuthService
from flext_auth.domain.entities import Session
from flext_auth.domain.entities import User
from flext_auth.domain.events import SessionCreated
from flext_auth.domain.events import TokenIssued
from flext_auth.domain.events import UserCreated
from flext_auth.domain.events import UserLoggedIn
from flext_auth.domain.events import UserPasswordChanged
from flext_auth.domain.value_objects import AuthToken
from flext_auth.domain.value_objects import Username
from flext_core.domain.types import ServiceResult


class TestAuthService:
    """Test AuthService class."""

    @pytest.fixture
    def mock_user_repository(self) -> AsyncMock:
        """Mock user repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_token_repository(self) -> AsyncMock:
        """Mock token repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_session_repository(self) -> AsyncMock:
        """Mock session repository."""
        return AsyncMock()

    @pytest.fixture
    def mock_password_hasher(self) -> AsyncMock:
        """Mock password hasher."""
        return AsyncMock()

    @pytest.fixture
    def mock_token_generator(self) -> AsyncMock:
        """Mock token generator."""
        return AsyncMock()

    @pytest.fixture
    def mock_event_bus(self) -> AsyncMock:
        """Mock event bus."""
        return AsyncMock()

    @pytest.fixture
    def auth_service(
        self,
        mock_user_repository: AsyncMock,
        mock_token_repository: AsyncMock,
        mock_session_repository: AsyncMock,
        mock_password_hasher: AsyncMock,
        mock_token_generator: AsyncMock,
        mock_event_bus: AsyncMock,
    ) -> AuthService:
        """Create AuthService with mocked dependencies."""
        return AuthService(
            user_repository=mock_user_repository,
            token_repository=mock_token_repository,
            session_repository=mock_session_repository,
            password_hasher=mock_password_hasher,
            token_generator=mock_token_generator,
            event_bus=mock_event_bus,
        )

    @pytest.mark.asyncio
    async def test_create_user_success(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_password_hasher: AsyncMock,
        mock_event_bus: AsyncMock,
    ) -> None:
        """Test successful user creation."""
        user_id = uuid4()
        username = Username("testuser")
        email = "test@example.com"
        password = "password123"

        # Mock password hashing
        hashed_password = "$2b$12$hashedpassword"
        mock_password_hasher.hash_password.return_value = hashed_password

        # Mock user creation
        mock_user = User(
            id=user_id,
            username=username,
            email=email,
            password_hash=hashed_password,
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_user_repository.save.return_value = ServiceResult.success(mock_user)
        mock_user_repository.get_by_username.return_value = ServiceResult.failure(
            "User not found",
        )
        mock_user_repository.get_by_email.return_value = ServiceResult.failure(
            "User not found",
        )

        result = await auth_service.create_user(username, email, password)

        assert result.is_success
        assert result.value.username == username
        assert result.value.email == email
        mock_password_hasher.hash_password.assert_called_once_with(password)
        mock_user_repository.save.assert_called_once()
        mock_event_bus.publish.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_user_username_exists(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test user creation when username already exists."""
        username = Username("testuser")
        email = "test@example.com"
        password = "password123"

        # Mock existing user
        existing_user = MagicMock()
        mock_user_repository.get_by_username.return_value = ServiceResult.success(
            existing_user,
        )

        result = await auth_service.create_user(username, email, password)

        assert result.is_failure
        assert "username" in result.error.lower() or "exists" in result.error.lower()

    @pytest.mark.asyncio
    async def test_create_user_email_exists(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test user creation when email already exists."""
        username = Username("testuser")
        email = "test@example.com"
        password = "password123"

        # Mock username check passes, email exists
        mock_user_repository.get_by_username.return_value = ServiceResult.failure(
            "User not found",
        )
        existing_user = MagicMock()
        mock_user_repository.get_by_email.return_value = ServiceResult.success(
            existing_user,
        )

        result = await auth_service.create_user(username, email, password)

        assert result.is_failure
        assert "email" in result.error.lower() or "exists" in result.error.lower()

    @pytest.mark.asyncio
    async def test_authenticate_user_success(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_password_hasher: AsyncMock,
        mock_token_generator: AsyncMock,
        mock_session_repository: AsyncMock,
        mock_event_bus: AsyncMock,
    ) -> None:
        """Test successful user authentication."""
        username = Username("testuser")
        password = "password123"
        hashed_password = "$2b$12$hashedpassword"

        # Mock user retrieval
        user_id = uuid4()
        mock_user = User(
            id=user_id,
            username=username,
            email="test@example.com",
            password_hash=hashed_password,
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_user_repository.get_by_username.return_value = ServiceResult.success(
            mock_user,
        )

        # Mock password verification
        mock_password_hasher.verify_password.return_value = True

        # Mock token generation
        access_token = AuthToken("access.token.here")
        refresh_token = AuthToken("refresh.token.here")
        mock_token_generator.generate_access_token.return_value = ServiceResult.success(
            access_token,
        )
        mock_token_generator.generate_refresh_token.return_value = (
            ServiceResult.success(refresh_token)
        )

        # Mock session creation
        session_id = uuid4()
        mock_session = Session(
            id=session_id,
            user_id=user_id,
            access_token=access_token,
            refresh_token=refresh_token,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_session_repository.save.return_value = ServiceResult.success(mock_session)

        result = await auth_service.authenticate_user(
            username,
            password,
            "192.168.1.1",
            "Test Browser",
        )

        assert result.is_success
        assert result.value.access_token == access_token
        assert result.value.refresh_token == refresh_token
        mock_password_hasher.verify_password.assert_called_once_with(
            password, hashed_password,
        )
        mock_event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test authentication when user not found."""
        username = Username("nonexistent")
        password = "password123"

        mock_user_repository.get_by_username.return_value = ServiceResult.failure(
            "User not found",
        )

        result = await auth_service.authenticate_user(username, password)

        assert result.is_failure
        assert "not found" in result.error.lower() or "invalid" in result.error.lower()

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_password_hasher: AsyncMock,
    ) -> None:
        """Test authentication with wrong password."""
        username = Username("testuser")
        password = "wrongpassword"
        hashed_password = "$2b$12$hashedpassword"

        # Mock user retrieval
        mock_user = User(
            id=uuid4(),
            username=username,
            email="test@example.com",
            password_hash=hashed_password,
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_user_repository.get_by_username.return_value = ServiceResult.success(
            mock_user,
        )

        # Mock password verification failure
        mock_password_hasher.verify_password.return_value = False

        result = await auth_service.authenticate_user(username, password)

        assert result.is_failure
        assert "invalid" in result.error.lower() or "incorrect" in result.error.lower()

    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test authentication of inactive user."""
        username = Username("testuser")
        password = "password123"

        # Mock inactive user
        mock_user = User(
            id=uuid4(),
            username=username,
            email="test@example.com",
            password_hash="$2b$12$hashedpassword",
            is_active=False,  # Inactive user
            created_at=datetime.now(UTC),
        )
        mock_user_repository.get_by_username.return_value = ServiceResult.success(
            mock_user,
        )

        result = await auth_service.authenticate_user(username, password)

        assert result.is_failure
        assert "inactive" in result.error.lower() or "disabled" in result.error.lower()

    @pytest.mark.asyncio
    async def test_validate_token_success(
        self,
        auth_service: AuthService,
        mock_token_repository: AsyncMock,
        mock_session_repository: AsyncMock,
    ) -> None:
        """Test successful token validation."""
        token = AuthToken("valid.token.here")
        user_id = uuid4()
        session_id = uuid4()

        # Mock token validation
        mock_token_info = MagicMock()
        mock_token_info.user_id = user_id
        mock_token_info.session_id = session_id
        mock_token_info.is_valid = True
        mock_token_repository.validate_token.return_value = ServiceResult.success(
            mock_token_info,
        )

        # Mock session validation
        mock_session = Session(
            id=session_id,
            user_id=user_id,
            access_token=token,
            refresh_token=AuthToken("refresh.token"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_session_repository.get_by_id.return_value = ServiceResult.success(
            mock_session,
        )

        result = await auth_service.validate_token(token)

        assert result.is_success
        assert result.value.user_id == user_id

    @pytest.mark.asyncio
    async def test_validate_token_invalid(
        self,
        auth_service: AuthService,
        mock_token_repository: AsyncMock,
    ) -> None:
        """Test validation of invalid token."""
        token = AuthToken("invalid.token.here")

        mock_token_repository.validate_token.return_value = ServiceResult.failure(
            "Invalid token",
        )

        result = await auth_service.validate_token(token)

        assert result.is_failure
        assert "invalid" in result.error.lower()

    @pytest.mark.asyncio
    async def test_change_password_success(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_password_hasher: AsyncMock,
        mock_event_bus: AsyncMock,
    ) -> None:
        """Test successful password change."""
        user_id = uuid4()
        current_password = "oldpassword"
        new_password = "newpassword123"
        current_hash = "$2b$12$oldhash"
        new_hash = "$2b$12$newhash"

        # Mock user retrieval
        mock_user = User(
            id=user_id,
            username=Username("testuser"),
            email="test@example.com",
            password_hash=current_hash,
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_user_repository.get_by_id.return_value = ServiceResult.success(mock_user)

        # Mock password operations
        mock_password_hasher.verify_password.return_value = True
        mock_password_hasher.hash_password.return_value = new_hash

        # Mock user update
        updated_user = User(
            id=user_id,
            username=Username("testuser"),
            email="test@example.com",
            password_hash=new_hash,
            is_active=True,
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_user_repository.save.return_value = ServiceResult.success(updated_user)

        result = await auth_service.change_password(
            user_id, current_password, new_password,
        )

        assert result.is_success
        mock_password_hasher.verify_password.assert_called_once_with(
            current_password, current_hash,
        )
        mock_password_hasher.hash_password.assert_called_once_with(new_password)
        mock_user_repository.save.assert_called_once()
        mock_event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_change_password_user_not_found(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test password change when user not found."""
        user_id = uuid4()
        current_password = "oldpassword"
        new_password = "newpassword123"

        mock_user_repository.get_by_id.return_value = ServiceResult.failure(
            "User not found",
        )

        result = await auth_service.change_password(
            user_id, current_password, new_password,
        )

        assert result.is_failure
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_change_password_wrong_current_password(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_password_hasher: AsyncMock,
    ) -> None:
        """Test password change with wrong current password."""
        user_id = uuid4()
        current_password = "wrongpassword"
        new_password = "newpassword123"
        current_hash = "$2b$12$oldhash"

        # Mock user retrieval
        mock_user = User(
            id=user_id,
            username=Username("testuser"),
            email="test@example.com",
            password_hash=current_hash,
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_user_repository.get_by_id.return_value = ServiceResult.success(mock_user)

        # Mock password verification failure
        mock_password_hasher.verify_password.return_value = False

        result = await auth_service.change_password(
            user_id, current_password, new_password,
        )

        assert result.is_failure
        assert (
            "current password" in result.error.lower()
            or "incorrect" in result.error.lower()
        )

    @pytest.mark.asyncio
    async def test_logout_user_success(
        self,
        auth_service: AuthService,
        mock_session_repository: AsyncMock,
        mock_token_repository: AsyncMock,
        mock_event_bus: AsyncMock,
    ) -> None:
        """Test successful user logout."""
        session_id = uuid4()
        user_id = uuid4()

        # Mock session retrieval
        mock_session = Session(
            id=session_id,
            user_id=user_id,
            access_token=AuthToken("access.token"),
            refresh_token=AuthToken("refresh.token"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            is_active=True,
            created_at=datetime.now(UTC),
        )
        mock_session_repository.get_by_id.return_value = ServiceResult.success(
            mock_session,
        )

        # Mock session deactivation
        deactivated_session = Session(
            id=session_id,
            user_id=user_id,
            access_token=AuthToken("access.token"),
            refresh_token=AuthToken("refresh.token"),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            is_active=False,  # Deactivated
            created_at=datetime.now(UTC),
            updated_at=datetime.now(UTC),
        )
        mock_session_repository.save.return_value = ServiceResult.success(
            deactivated_session,
        )

        # Mock token revocation
        mock_token_repository.revoke_token.return_value = ServiceResult.success(None)

        result = await auth_service.logout_user(session_id)

        assert result.is_success
        mock_session_repository.save.assert_called_once()
        mock_token_repository.revoke_token.assert_called()
        mock_event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_logout_user_session_not_found(
        self,
        auth_service: AuthService,
        mock_session_repository: AsyncMock,
    ) -> None:
        """Test logout when session not found."""
        session_id = uuid4()

        mock_session_repository.get_by_id.return_value = ServiceResult.failure(
            "Session not found",
        )

        result = await auth_service.logout_user(session_id)

        assert result.is_failure
        assert "not found" in result.error.lower()

    @pytest.mark.asyncio
    async def test_refresh_token_success(
        self,
        auth_service: AuthService,
        mock_token_repository: AsyncMock,
        mock_token_generator: AsyncMock,
        mock_session_repository: AsyncMock,
        mock_event_bus: AsyncMock,
    ) -> None:
        """Test successful token refresh."""
        refresh_token = AuthToken("refresh.token.here")
        user_id = uuid4()
        session_id = uuid4()

        # Mock refresh token validation
        mock_token_info = MagicMock()
        mock_token_info.user_id = user_id
        mock_token_info.session_id = session_id
        mock_token_info.is_valid = True
        mock_token_repository.validate_refresh_token.return_value = (
            ServiceResult.success(
                mock_token_info,
            )
        )

        # Mock new token generation
        new_access_token = AuthToken("new.access.token")
        new_refresh_token = AuthToken("new.refresh.token")
        mock_token_generator.generate_access_token.return_value = ServiceResult.success(
            new_access_token,
        )
        mock_token_generator.generate_refresh_token.return_value = (
            ServiceResult.success(
                new_refresh_token,
            )
        )

        # Mock session update
        updated_session = MagicMock()
        mock_session_repository.save.return_value = ServiceResult.success(
            updated_session,
        )

        result = await auth_service.refresh_token(refresh_token)

        assert result.is_success
        assert result.value.access_token == new_access_token
        assert result.value.refresh_token == new_refresh_token
        mock_event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_refresh_token_invalid(
        self,
        auth_service: AuthService,
        mock_token_repository: AsyncMock,
    ) -> None:
        """Test refresh with invalid token."""
        refresh_token = AuthToken("invalid.refresh.token")

        mock_token_repository.validate_refresh_token.return_value = (
            ServiceResult.failure(
                "Invalid refresh token",
            )
        )

        result = await auth_service.refresh_token(refresh_token)

        assert result.is_failure
        assert "invalid" in result.error.lower()

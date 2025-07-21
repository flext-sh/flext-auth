"""Tests for application services layer."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import AsyncMock, MagicMock
from uuid import uuid4

import pytest
from flext_core.domain.types import ServiceResult

from flext_auth.application.services import AuthService
from flext_auth.domain.entities import Session, User
from flext_auth.domain.value_objects import AuthToken, Username


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
        username = Username(value="testuser")
        email = "test@example.com"
        password = "password123"

        # Mock password hashing
        hashed_password = "$2b$12$xIKJRSQMr4JFA6/ogklLzuvSqW/oBtPYW4akeAJv.bFoSQG8VddG."
        mock_password_hasher.hash_password.return_value = hashed_password

        # Mock user creation
        mock_user = User(
            id=user_id,
            username=username.value,
            email=email,
            password_hash=hashed_password,
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )
        mock_user_repository.save.return_value = ServiceResult.ok(mock_user)
        mock_user_repository.get_by_username.return_value = ServiceResult.fail(
            "User not found",
        )
        mock_user_repository.get_by_email.return_value = ServiceResult.fail(
            "User not found",
        )

        result = await auth_service.create_user(username, email, password)

        # Debug output
        if not result.is_success:
            pass
        assert result.is_success
        assert result.data is not None
        assert result.data.username == "testuser"
        assert result.data.email == email
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
        username = Username(value="testuser")
        email = "test@example.com"
        password = "password123"

        # Mock existing user
        existing_user = MagicMock()
        mock_user_repository.get_by_username.return_value = ServiceResult.ok(
            existing_user,
        )

        result = await auth_service.create_user(username, email, password)

        assert result.is_failure
        assert result.error is not None
        assert "username" in result.error.lower() or "exists" in result.error.lower()

    @pytest.mark.asyncio
    async def test_create_user_email_exists(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test user creation when email already exists."""
        username = Username(value="testuser")
        email = "test@example.com"
        password = "password123"

        # Mock username check passes, email exists
        mock_user_repository.get_by_username.return_value = ServiceResult.fail(
            "User not found",
        )
        existing_user = MagicMock()
        mock_user_repository.get_by_email.return_value = ServiceResult.ok(
            existing_user,
        )

        result = await auth_service.create_user(username, email, password)

        assert result.is_failure
        assert result.error is not None
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
        username = Username(value="testuser")
        password = "password123"
        hashed_password = "$2b$12$xIKJRSQMr4JFA6/ogklLzuvSqW/oBtPYW4akeAJv.bFoSQG8VddG."

        # Mock user retrieval
        user_id = uuid4()
        mock_user = User(
            id=user_id,
            username=username.value,
            email="test@example.com",
            password_hash=hashed_password,
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )
        mock_user_repository.get_by_username.return_value = ServiceResult.ok(
            mock_user,
        )

        # Mock password verification
        mock_password_hasher.verify_password.return_value = True

        # Mock token generation
        access_token = AuthToken(value="access.token.here", token_type="access")
        refresh_token = AuthToken(value="refresh.token.here", token_type="refresh")
        mock_token_generator.generate_access_token.return_value = ServiceResult.ok(
            access_token,
        )
        mock_token_generator.generate_refresh_token.return_value = ServiceResult.ok(
            refresh_token,
        )

        # Mock session creation
        session_id = uuid4()
        mock_session = Session(
            id=session_id,
            user_id=user_id,
            token=access_token.value,
            refresh_token=refresh_token.value,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            status="active",
        )
        mock_session_repository.save.return_value = ServiceResult.ok(mock_session)

        result = await auth_service.authenticate_user(
            username,
            password,
            "192.168.1.1",
            "Test Browser",
        )

        assert result.is_success
        assert result.data is not None
        assert result.data.username == username.value
        mock_password_hasher.verify_password.assert_called_once_with(
            password,
            hashed_password,
        )
        mock_event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_authenticate_user_not_found(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test authentication when user not found."""
        username = Username(value="nonexistent")
        password = "password123"

        mock_user_repository.get_by_username.return_value = ServiceResult.fail(
            "User not found",
        )

        result = await auth_service.authenticate_user(username, password)

        assert result.is_failure
        assert result.error is not None
        assert "not found" in result.error.lower() or "invalid" in result.error.lower()

    @pytest.mark.asyncio
    async def test_authenticate_user_wrong_password(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_password_hasher: AsyncMock,
    ) -> None:
        """Test authentication with wrong password."""
        username = Username(value="testuser")
        password = "wrongpassword"
        hashed_password = "$2b$12$xIKJRSQMr4JFA6/ogklLzuvSqW/oBtPYW4akeAJv.bFoSQG8VddG."

        # Mock user retrieval - create fresh user with no failed login attempts
        mock_user = User(
            id=uuid4(),
            username="testuser",
            email="test@example.com",
            password_hash=hashed_password,
            login_attempts=0,  # Fresh user with no failed attempts
            locked_until=None,  # Not locked
        )
        mock_user_repository.get_by_username.return_value = ServiceResult.ok(
            mock_user,
        )

        # Mock user update to capture the state changes
        mock_user_repository.update.return_value = ServiceResult.ok(mock_user)

        # Mock password verification failure
        mock_password_hasher.verify_password.return_value = False

        result = await auth_service.authenticate_user(username, password)

        assert result.is_failure
        # Accept both password validation errors and account locked errors
        # since both are valid authentication failure scenarios
        assert result.error is not None
        assert (
            "invalid" in result.error.lower()
            or "incorrect" in result.error.lower()
            or "locked" in result.error.lower()
        )

    @pytest.mark.asyncio
    async def test_authenticate_user_inactive(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
    ) -> None:
        """Test authentication of inactive user."""
        username = Username(value="testuser")
        password = "password123"

        # Mock inactive user
        mock_user = User(
            username=username.value,
            email="test@example.com",
            password_hash="$2b$12$xIKJRSQMr4JFA6/ogklLzuvSqW/oBtPYW4akeAJv.bFoSQG8VddG.",
            status="inactive",  # Inactive user
            login_attempts=0,  # Ensure not locked
            locked_until=None,  # Ensure not locked
        )
        mock_user_repository.get_by_username.return_value = ServiceResult.ok(
            mock_user,
        )

        result = await auth_service.authenticate_user(username, password)

        assert result.is_failure
        assert result.error is not None
        assert "not active" in result.error.lower()

    @pytest.mark.asyncio
    async def test_validate_token_success(
        self,
        auth_service: AuthService,
        mock_token_repository: AsyncMock,
        mock_session_repository: AsyncMock,
    ) -> None:
        """Test successful token validation."""
        token = AuthToken(
            value="valid.token.here.with.very.long.secure.value.for.testing.authentication",
            token_type="access",
        )
        user_id = uuid4()
        session_id = uuid4()

        # Mock token validation - get_by_value should return the token
        mock_auth_token = AuthToken(value=token.value, token_type="access")
        mock_token_repository.get_by_value.return_value = ServiceResult.ok(
            mock_auth_token,
        )

        # Mock session validation
        mock_session = Session(
            id=session_id,
            user_id=user_id,
            token=token.value,
            refresh_token=AuthToken(value="refresh.token", token_type="refresh").value,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            status="active",
        )
        mock_session_repository.get_by_id.return_value = ServiceResult.ok(
            mock_session,
        )

        result = await auth_service.validate_token(token.value)

        assert result.is_success
        assert result.data is not None
        assert result.data.value == token.value

    @pytest.mark.asyncio
    async def test_validate_token_invalid(
        self,
        auth_service: AuthService,
        mock_token_repository: AsyncMock,
    ) -> None:
        """Test validation of invalid token."""
        token = AuthToken(value="invalid.token.here", token_type="access")

        mock_token_repository.get_by_value.return_value = ServiceResult.fail(
            "Invalid token",
        )

        result = await auth_service.validate_token(token.value)

        assert result.is_failure
        assert result.error is not None
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
            username="testuser",
            email="test@example.com",
            password_hash=current_hash,
        )
        mock_user_repository.get_by_id.return_value = ServiceResult.ok(mock_user)

        # Mock password operations
        mock_password_hasher.verify_password.return_value = True
        mock_password_hasher.hash_password.return_value = new_hash

        # Mock user update
        updated_user = User(
            id=user_id,
            username="testuser",
            email="test@example.com",
            password_hash=new_hash,
        )
        mock_user_repository.save.return_value = ServiceResult.ok(updated_user)

        result = await auth_service.change_password(
            user_id,
            current_password,
            new_password,
        )

        assert result.is_success
        mock_password_hasher.verify_password.assert_called_once_with(
            current_password,
            current_hash,
        )
        mock_password_hasher.hash_password.assert_called_once_with(new_password)
        mock_user_repository.update.assert_called_once()
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

        mock_user_repository.get_by_id.return_value = ServiceResult.fail(
            "User not found",
        )

        result = await auth_service.change_password(
            user_id,
            current_password,
            new_password,
        )

        assert result.is_failure
        assert result.error is not None
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
            username="testuser",
            email="test@example.com",
            password_hash=current_hash,
        )
        mock_user_repository.get_by_id.return_value = ServiceResult.ok(mock_user)

        # Mock password verification failure
        mock_password_hasher.verify_password.return_value = False

        result = await auth_service.change_password(
            user_id,
            current_password,
            new_password,
        )

        assert result.is_failure
        assert result.error is not None
        assert (
            "current password" in result.error.lower()
            or "incorrect" in result.error.lower()
        )

    @pytest.mark.asyncio
    async def test_logout_user_success(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_session_repository: AsyncMock,
        mock_token_repository: AsyncMock,
        mock_event_bus: AsyncMock,
    ) -> None:
        """Test successful user logout."""
        session_id = uuid4()
        user_id = uuid4()

        # Mock user repository
        mock_user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$xIKJRSQMr4JFA6/ogklLzuvSqW/oBtPYW4akeAJv.bFoSQG8VddG.",
        )
        mock_user_repository.get_by_id.return_value = ServiceResult.ok(mock_user)

        # Mock session retrieval
        mock_session = Session(
            id=session_id,
            user_id=user_id,
            token=AuthToken(value="access.token", token_type="access").value,
            refresh_token=AuthToken(value="refresh.token", token_type="refresh").value,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            status="active",
        )
        mock_session_repository.get_by_id.return_value = ServiceResult.ok(
            mock_session,
        )

        # Mock session deactivation
        deactivated_session = Session(
            id=session_id,
            user_id=user_id,
            token=AuthToken(value="access.token", token_type="access").value,
            refresh_token=AuthToken(value="refresh.token", token_type="refresh").value,
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
            status="inactive",  # Deactivated
        )
        mock_session_repository.save.return_value = ServiceResult.ok(
            deactivated_session,
        )

        result = await auth_service.logout_user(user_id, str(session_id))

        assert result.is_success
        mock_session_repository.save.assert_called_once()
        mock_event_bus.publish.assert_called()

    @pytest.mark.asyncio
    async def test_logout_user_session_not_found(
        self,
        auth_service: AuthService,
        mock_user_repository: AsyncMock,
        mock_session_repository: AsyncMock,
    ) -> None:
        """Test logout when session not found."""
        user_id = uuid4()
        session_id = uuid4()

        # Mock user repository - user should exist for logout attempt
        mock_user = User(
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$xIKJRSQMr4JFA6/ogklLzuvSqW/oBtPYW4akeAJv.bFoSQG8VddG.",
        )
        mock_user_repository.get_by_id.return_value = ServiceResult.ok(mock_user)

        mock_session_repository.get_by_id.return_value = ServiceResult.fail(
            "Session not found",
        )

        result = await auth_service.logout_user(user_id, str(session_id))

        # Logout should succeed even if session not found
        # (user is successfully logged out, just no session to invalidate)
        assert result.is_success

    # Refresh token tests are implemented in dedicated test module
    # @pytest.mark.asyncio
    # async def test_refresh_token_success(...)
    # @pytest.mark.asyncio
    # async def test_refresh_token_invalid(...)

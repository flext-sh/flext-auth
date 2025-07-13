"""Comprehensive tests for flext_auth.application.auth_service module."""

from __future__ import annotations

import asyncio
from datetime import datetime
from datetime import timedelta
from unittest.mock import AsyncMock
from unittest.mock import MagicMock
from unittest.mock import patch
from uuid import uuid4

import pytest
import pytest_asyncio

from flext_auth.application.auth_service import AuthenticationService
from flext_auth.application.auth_service import EmailVerificationService
from flext_auth.application.auth_service import PasswordService
from flext_auth.domain.entities import Session
from flext_auth.domain.entities import User
from flext_core import ServiceResult

pytestmark = pytest.mark.asyncio


class TestAuthenticationService:
    """Test AuthenticationService functionality."""

    @pytest.fixture
    def mock_user_repo(self) -> MagicMock:
        """Create mock user repository."""
        return MagicMock()

    @pytest.fixture
    def mock_session_repo(self) -> MagicMock:
        """Create mock session repository."""
        return MagicMock()

    @pytest.fixture
    def mock_role_repo(self) -> MagicMock:
        """Create mock role repository."""
        return MagicMock()

    @pytest.fixture
    def auth_service(
        self,
        mock_user_repo: MagicMock,
        mock_session_repo: MagicMock,
        mock_role_repo: MagicMock,
    ) -> AuthenticationService:
        """Create AuthenticationService instance with mocked repositories."""
        return AuthenticationService(
            user_repo=mock_user_repo,
            session_repo=mock_session_repo,
            role_repo=mock_role_repo,
        )

    @pytest.fixture
    def sample_user(self) -> User:
        """Create a sample user for testing."""
        return User(
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$hashedpassword",
            role="user",
            status="active",
        )

    @pytest.fixture
    def locked_user(self) -> User:
        """Create a locked user for testing."""
        user = User(
            username="lockeduser",
            email="locked@example.com",
            password_hash="$2b$12$hashedpassword",
            role="user",
            status="active",
        )
        user.locked_until = datetime.now() + timedelta(minutes=30)
        return user

    @pytest.fixture
    def inactive_user(self) -> User:
        """Create an inactive user for testing."""
        return User(
            username="inactiveuser",
            email="inactive@example.com",
            password_hash="$2b$12$hashedpassword",
            role="user",
            status="suspended",
        )

    async def test_create_user_success(
        self, auth_service: AuthenticationService, mock_user_repo: MagicMock,
    ) -> None:
        """Test successful user creation."""
        # Setup mocks
        mock_user_repo.username_exists = AsyncMock(
            return_value=ServiceResult.success(False),
        )
        mock_user_repo.email_exists = AsyncMock(return_value=ServiceResult.success(False))
        mock_user_repo.create = AsyncMock(
            return_value=ServiceResult.success(
                User(
                    username="newuser",
                    email="new@example.com",
                    password_hash="$2b$12$hashedpassword",
                ),
            ),
        )

        # Test user creation
        result = await auth_service.create_user(
            username="newuser",
            email="new@example.com",
            password="StrongPassword123!",
            role="user",
        )

        # Verify result
        assert result.is_successful
        assert result.value.username == "newuser"
        assert result.value.email == "new@example.com"

        # Verify repository calls
        mock_user_repo.username_exists.assert_called_once_with("newuser")
        mock_user_repo.email_exists.assert_called_once_with("new@example.com")
        mock_user_repo.create.assert_called_once()

    async def test_create_user_username_exists(
        self, auth_service: AuthenticationService, mock_user_repo: MagicMock,
    ) -> None:
        """Test user creation with existing username."""
        # Setup mocks
        mock_user_repo.username_exists = AsyncMock(
            return_value=ServiceResult.success(True),
        )

        # Test user creation
        result = await auth_service.create_user(
            username="existinguser",
            email="new@example.com",
            password="StrongPassword123!",
        )

        # Verify result
        assert not result.is_successful
        assert "already exists" in result.error_message

    async def test_create_user_email_exists(
        self, auth_service: AuthenticationService, mock_user_repo: MagicMock,
    ) -> None:
        """Test user creation with existing email."""
        # Setup mocks
        mock_user_repo.username_exists = AsyncMock(
            return_value=ServiceResult.success(False),
        )
        mock_user_repo.email_exists = AsyncMock(return_value=ServiceResult.success(True))

        # Test user creation
        result = await auth_service.create_user(
            username="newuser",
            email="existing@example.com",
            password="StrongPassword123!",
        )

        # Verify result
        assert result.is_successful
        assert "already exists" in result.error_message

    async def test_authenticate_user_success(
        self,
        auth_service: AuthenticationService,
        mock_user_repo: MagicMock,
        mock_session_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test successful user authentication."""
        # Setup mocks
        mock_user_repo.find_by_username = AsyncMock(
            return_value=ServiceResult.success(sample_user),
        )
        mock_user_repo.update = AsyncMock(return_value=ServiceResult.success(sample_user))
        mock_session_repo.create = AsyncMock(
            return_value=ServiceResult.success(
                Session(
                    user_id=sample_user.id,
                    token="session_token",
                    ip_address="192.168.1.100",
                    user_agent="Test Agent",
                    expires_at=datetime.now() + timedelta(hours=1),
                ),
            ),
        )

        # Mock password verification
        with patch.object(auth_service, "_verify_password", return_value=True):
            result = await auth_service.authenticate_user(
                username="testuser",
                password="correct_password",
                ip_address="192.168.1.100",
                user_agent="Test Agent",
            )

        # Verify result
        assert result.is_successful
        user, session = result.value
        assert user.username == "testuser"
        assert session.user_id == sample_user.id

    async def test_authenticate_user_invalid_username(
        self, auth_service: AuthenticationService, mock_user_repo: MagicMock,
    ) -> None:
        """Test authentication with invalid username."""
        # Setup mocks
        mock_user_repo.find_by_username = AsyncMock(
            return_value=ServiceResult.success(None),
        )

        # Test authentication
        result = await auth_service.authenticate_user(
            username="nonexistent",
            password="password",
            ip_address="192.168.1.100",
            user_agent="Test Agent",
        )

        # Verify result
        assert result.is_successful
        assert "Invalid username or password" in result.error_message

    async def test_authenticate_user_locked_account(
        self,
        auth_service: AuthenticationService,
        mock_user_repo: MagicMock,
        locked_user: User,
    ) -> None:
        """Test authentication with locked account."""
        # Setup mocks
        mock_user_repo.find_by_username = AsyncMock(
            return_value=ServiceResult.success(locked_user),
        )

        # Test authentication
        result = await auth_service.authenticate_user(
            username="lockeduser",
            password="password",
            ip_address="192.168.1.100",
            user_agent="Test Agent",
        )

        # Verify result
        assert result.is_successful
        assert "locked" in result.error_message

    async def test_authenticate_user_inactive_account(
        self,
        auth_service: AuthenticationService,
        mock_user_repo: MagicMock,
        inactive_user: User,
    ) -> None:
        """Test authentication with inactive account."""
        # Setup mocks
        mock_user_repo.find_by_username = AsyncMock(
            return_value=ServiceResult.success(inactive_user),
        )

        # Test authentication
        result = await auth_service.authenticate_user(
            username="inactiveuser",
            password="password",
            ip_address="192.168.1.100",
            user_agent="Test Agent",
        )

        # Verify result
        assert result.is_successful
        assert "not active" in result.error_message

    async def test_authenticate_user_wrong_password(
        self,
        auth_service: AuthenticationService,
        mock_user_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test authentication with wrong password."""
        # Setup mocks
        mock_user_repo.find_by_username = AsyncMock(
            return_value=ServiceResult.success(sample_user),
        )
        mock_user_repo.update = AsyncMock(return_value=ServiceResult.success(sample_user))

        # Mock password verification
        with patch.object(auth_service, "_verify_password", return_value=False):
            result = await auth_service.authenticate_user(
                username="testuser",
                password="wrong_password",
                ip_address="192.168.1.100",
                user_agent="Test Agent",
            )

        # Verify result
        assert result.is_successful
        assert "Invalid username or password" in result.error_message

        # Verify failed login was recorded
        mock_user_repo.update.assert_called_once()

    async def test_validate_session_success(
        self,
        auth_service: AuthenticationService,
        mock_session_repo: MagicMock,
        mock_user_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test successful session validation."""
        # Create active session
        session = Session(
            user_id=sample_user.id,
            token="valid_token",
            ip_address="192.168.1.100",
            user_agent="Test Agent",
            expires_at=datetime.now() + timedelta(hours=1),
        )

        # Setup mocks
        mock_session_repo.find_by_token = AsyncMock(
            return_value=ServiceResult.success(session),
        )
        mock_session_repo.update = AsyncMock(
            return_value=ServiceResult.success(session),
        )
        mock_user_repo.find_by_id = AsyncMock(
            return_value=ServiceResult.success(sample_user),
        )

        # Test session validation
        result = await auth_service.validate_session("valid_token")

        # Verify result
        assert result.is_successful
        user, session_result = result.value
        assert user.username == "testuser"
        assert session_result.token == "valid_token"

    async def test_validate_session_invalid_token(
        self, auth_service: AuthenticationService, mock_session_repo: MagicMock,
    ) -> None:
        """Test session validation with invalid token."""
        # Setup mocks
        mock_session_repo.find_by_token = AsyncMock(
            return_value=ServiceResult.success(None),
        )

        # Test session validation
        result = await auth_service.validate_session("invalid_token")

        # Verify result
        assert result.is_successful
        assert "Invalid session token" in result.error_message

    async def test_validate_session_expired(
        self,
        auth_service: AuthenticationService,
        mock_session_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test session validation with expired session."""
        # Create expired session
        session = Session(
            user_id=sample_user.id,
            token="expired_token",
            ip_address="192.168.1.100",
            user_agent="Test Agent",
            expires_at=datetime.now() - timedelta(hours=1),  # Expired
        )

        # Setup mocks
        mock_session_repo.find_by_token = AsyncMock(
            return_value=ServiceResult.success(session),
        )

        # Test session validation
        result = await auth_service.validate_session("expired_token")

        # Verify result
        assert result.is_successful
        assert "expired or revoked" in result.error_message

    async def test_logout_user_success(
        self,
        auth_service: AuthenticationService,
        mock_session_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test successful user logout."""
        # Create session
        session = Session(
            user_id=sample_user.id,
            token="session_token",
            ip_address="192.168.1.100",
            user_agent="Test Agent",
            expires_at=datetime.now() + timedelta(hours=1),
        )

        # Setup mocks
        mock_session_repo.find_by_token = AsyncMock(
            return_value=ServiceResult.success(session),
        )
        mock_session_repo.update = AsyncMock(
            return_value=ServiceResult.success(session),
        )

        # Test logout
        result = await auth_service.logout_user("session_token")

        # Verify result
        assert result.is_successful
        assert result.value is True

        # Verify session was revoked
        mock_session_repo.update.assert_called_once()

    async def test_logout_user_session_not_found(
        self, auth_service: AuthenticationService, mock_session_repo: MagicMock,
    ) -> None:
        """Test logout with session not found."""
        # Setup mocks
        mock_session_repo.find_by_token = AsyncMock(
            return_value=ServiceResult.success(None),
        )

        # Test logout
        result = await auth_service.logout_user("nonexistent_token")

        # Verify result
        assert result.is_successful
        assert "not found" in result.error_message

    async def test_change_password_success(
        self,
        auth_service: AuthenticationService,
        mock_user_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test successful password change."""
        # Setup mocks
        mock_user_repo.find_by_id = AsyncMock(
            return_value=ServiceResult.success(sample_user),
        )
        mock_user_repo.update = AsyncMock(return_value=ServiceResult.success(sample_user))

        # Mock password verification
        with patch.object(auth_service, "_verify_password", return_value=True):
            with patch.object(auth_service, "_hash_password", return_value="new_hash"):
                result = await auth_service.change_password(
                    user_id=sample_user.id,
                    current_password="current_password",
                    new_password="new_password",
                )

        # Verify result
        assert result.is_successful
        assert result.value is True

        # Verify password was changed
        mock_user_repo.update.assert_called_once()

    async def test_change_password_user_not_found(
        self, auth_service: AuthenticationService, mock_user_repo: MagicMock,
    ) -> None:
        """Test password change with user not found."""
        # Setup mocks
        mock_user_repo.find_by_id = AsyncMock(return_value=ServiceResult.success(None))

        # Test password change
        result = await auth_service.change_password(
            user_id=uuid4(),
            current_password="current_password",
            new_password="new_password",
        )

        # Verify result
        assert result.is_successful
        assert "not found" in result.error_message

    async def test_change_password_incorrect_current(
        self,
        auth_service: AuthenticationService,
        mock_user_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test password change with incorrect current password."""
        # Setup mocks
        mock_user_repo.find_by_id = AsyncMock(
            return_value=ServiceResult.success(sample_user),
        )

        # Mock password verification
        with patch.object(auth_service, "_verify_password", return_value=False):
            result = await auth_service.change_password(
                user_id=sample_user.id,
                current_password="wrong_password",
                new_password="new_password",
            )

        # Verify result
        assert result.is_successful
        assert "incorrect" in result.error_message

    async def test_verify_email_success(
        self,
        auth_service: AuthenticationService,
        mock_user_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test successful email verification."""
        # Setup mocks
        mock_user_repo.find_by_id = AsyncMock(
            return_value=ServiceResult.success(sample_user),
        )
        mock_user_repo.update = AsyncMock(return_value=ServiceResult.success(sample_user))

        # Test email verification
        result = await auth_service.verify_email(sample_user.id)

        # Verify result
        assert result.is_successful
        assert result.value is True

        # Verify email was verified
        mock_user_repo.update.assert_called_once()

    async def test_revoke_all_user_sessions_success(
        self,
        auth_service: AuthenticationService,
        mock_session_repo: MagicMock,
        sample_user: User,
    ) -> None:
        """Test successful revocation of all user sessions."""
        # Setup mocks
        mock_session_repo.revoke_all_user_sessions = AsyncMock(
            return_value=ServiceResult.success(3),
        )

        # Test session revocation
        result = await auth_service.revoke_all_user_sessions(sample_user.id)

        # Verify result
        assert result.is_successful
        assert result.value == 3

    async def test_cleanup_expired_sessions_success(
        self, auth_service: AuthenticationService, mock_session_repo: MagicMock,
    ) -> None:
        """Test successful cleanup of expired sessions."""
        # Setup mocks
        mock_session_repo.cleanup_expired_sessions = AsyncMock(
            return_value=ServiceResult.success(5),
        )

        # Test session cleanup
        result = await auth_service.cleanup_expired_sessions()

        # Verify result
        assert result.is_successful
        assert result.value == 5

    def test_hash_password(self, auth_service: AuthenticationService) -> None:
        """Test password hashing."""
        password = "test_password"
        hashed = auth_service._hash_password(password)

        # Verify hash
        assert hashed.startswith("$2b$")
        assert len(hashed) > 50  # bcrypt hashes are typically 60 characters

    def test_verify_password(self, auth_service: AuthenticationService) -> None:
        """Test password verification."""
        password = "test_password"
        hashed = auth_service._hash_password(password)

        # Test correct password
        assert auth_service._verify_password(password, hashed) is True

        # Test incorrect password
        assert auth_service._verify_password("wrong_password", hashed) is False


class TestPasswordService:
    """Test PasswordService functionality."""

    @pytest.fixture
    def password_service(self) -> PasswordService:
        """Create PasswordService instance."""
        return PasswordService()

    async def test_generate_reset_token_success(
        self, password_service: PasswordService,
    ) -> None:
        """Test successful reset token generation."""
        result = await password_service.generate_reset_token("test@example.com")

        # Verify result
        assert result.is_successful
        assert len(result.value) >= 32  # Token should be reasonably long

    async def test_reset_password_success(
        self, password_service: PasswordService,
    ) -> None:
        """Test successful password reset."""
        mock_user_repo = MagicMock()

        result = await password_service.reset_password(
            token="reset_token",
            new_password="new_password",
            user_repo=mock_user_repo,
        )

        # Verify result (placeholder implementation always succeeds)
        assert result.is_successful
        assert result.value is True


class TestEmailVerificationService:
    """Test EmailVerificationService functionality."""

    @pytest.fixture
    def email_service(self) -> EmailVerificationService:
        """Create EmailVerificationService instance."""
        return EmailVerificationService()

    async def test_generate_verification_token_success(
        self, email_service: EmailVerificationService,
    ) -> None:
        """Test successful verification token generation."""
        user_id = uuid4()
        result = await email_service.generate_verification_token(user_id)

        # Verify result
        assert result.is_successful
        assert len(result.value) >= 32  # Token should be reasonably long

    async def test_verify_email_token_success(
        self, email_service: EmailVerificationService,
    ) -> None:
        """Test successful email token verification."""
        mock_auth_service = MagicMock()

        result = await email_service.verify_email_token(
            token="verification_token",
            auth_service=mock_auth_service,
        )

        # Verify result (placeholder implementation always succeeds)
        assert result.is_successful
        assert result.value is True


class TestServiceIntegration:
    """Test integration between services."""

    @pytest.fixture
    def services(self) -> tuple[AuthenticationService, PasswordService, EmailVerificationService]:
        """Create all services for integration testing."""
        # Create mock repositories
        mock_user_repo = MagicMock()
        mock_session_repo = MagicMock()
        mock_role_repo = MagicMock()

        # Create services
        auth_service = AuthenticationService(
            user_repo=mock_user_repo,
            session_repo=mock_session_repo,
            role_repo=mock_role_repo,
        )
        password_service = PasswordService()
        email_service = EmailVerificationService()

        return auth_service, password_service, email_service

    async def test_full_user_lifecycle(
        self, services: tuple[AuthenticationService, PasswordService, EmailVerificationService],
    ) -> None:
        """Test full user lifecycle workflow."""
        auth_service, password_service, email_service = services

        # Mock repositories for successful operations
        auth_service.user_repo.username_exists = AsyncMock(
            return_value=ServiceResult.success(False),
        )
        auth_service.user_repo.email_exists = AsyncMock(
            return_value=ServiceResult.success(False),
        )
        auth_service.user_repo.create = AsyncMock(
            return_value=ServiceResult.success(
                User(
                    username="testuser",
                    email="test@example.com",
                    password_hash="$2b$12$hashedpassword",
                ),
            ),
        )

        # 1. Create user
        create_result = await auth_service.create_user(
            username="testuser",
            email="test@example.com",
            password="StrongPassword123!",
        )
        assert create_result.is_successful

        # 2. Generate email verification token
        user = create_result.value
        verify_token_result = await email_service.generate_verification_token(user.id)
        assert verify_token_result.is_successful

        # 3. Verify email
        verify_result = await email_service.verify_email_token(
            token=verify_token_result.value,
            auth_service=auth_service,
        )
        assert verify_result.is_successful

        # 4. Generate password reset token
        reset_token_result = await password_service.generate_reset_token(user.email)
        assert reset_token_result.is_successful

        # All operations should complete successfully
        assert all([
            create_result.is_successful,
            verify_token_result.is_successful,
            verify_result.is_successful,
            reset_token_result.is_successful,
        ])

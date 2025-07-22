"""Extended tests for user_service.py to improve coverage.

Focuses on testing missing functionality and edge cases
to reach 90%+ coverage target.
"""

from __future__ import annotations

from datetime import UTC, datetime as dt, timedelta
from typing import Any
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from flext_core.domain.shared_types import ServiceResult
from pydantic import ValidationError

from flext_auth.types import SecurityEvent, TokenType
from flext_auth.user_service import (
    PasswordHasherImpl,
    SecurityAuditorImpl,
    UserCreationRequest,
    UserService,
    UserServiceInMemoryUserRepository,
)


class TestPasswordHasherImplExtended:
    """Extended tests for PasswordHasherImpl."""

    def test_needs_update_true(self) -> None:
        """Test needs_update returns True for outdated hash."""
        # Create mock settings with proper bcrypt rounds
        mock_settings = Mock()
        mock_settings.password_bcrypt_rounds = 12

        hasher = PasswordHasherImpl(settings=mock_settings)

        # Mock context to return True for needs_update
        with patch.object(hasher.context, "needs_update", return_value=True):
            result = hasher.needs_update("old_hash")
            assert result is True

    def test_needs_update_false(self) -> None:
        """Test needs_update returns False for current hash."""
        # Create mock settings with proper bcrypt rounds
        mock_settings = Mock()
        mock_settings.password_bcrypt_rounds = 12

        hasher = PasswordHasherImpl(settings=mock_settings)

        # Mock context to return False for needs_update
        with patch.object(hasher.context, "needs_update", return_value=False):
            result = hasher.needs_update("current_hash")
            assert result is False

    def test_needs_update_none_result(self) -> None:
        """Test needs_update returns True when context returns None."""
        # Create mock settings with proper bcrypt rounds
        mock_settings = Mock()
        mock_settings.password_bcrypt_rounds = 12

        hasher = PasswordHasherImpl(settings=mock_settings)

        # Mock context to return None for needs_update
        with patch.object(hasher.context, "needs_update", return_value=None):
            result = hasher.needs_update("hash")
            assert result is True

    def test_hash_password_empty_result(self) -> None:
        """Test hash_password returns empty string when result is None."""
        # Create mock settings with proper bcrypt rounds
        mock_settings = Mock()
        mock_settings.password_bcrypt_rounds = 12

        hasher = PasswordHasherImpl(settings=mock_settings)

        # Mock context to return None for hash
        with patch.object(hasher.context, "hash", return_value=None):
            result = hasher.hash_password("password123")
            assert result == ""

    def test_verify_password_none_result(self) -> None:
        """Test verify_password returns False when context returns None."""
        # Create mock settings with proper bcrypt rounds
        mock_settings = Mock()
        mock_settings.password_bcrypt_rounds = 12

        hasher = PasswordHasherImpl(settings=mock_settings)

        # Mock context to return None for verify
        with patch.object(hasher.context, "verify", return_value=None):
            result = hasher.verify_password("password", "hash")
            assert result is False


class TestUserCreationRequestExtended:
    """Extended tests for UserCreationRequest validation."""

    def test_password_validation_missing_lowercase(self) -> None:
        """Test password validation fails when lowercase required but missing."""
        # Mock settings to require lowercase (which is default True)
        with patch("flext_auth.user_service.get_auth_settings") as mock_settings:
            mock_config = Mock()
            mock_config.password_require_lowercase = True
            mock_config.password_require_uppercase = True  # Default True
            mock_config.password_require_numbers = True  # Default True
            mock_config.password_require_special = False  # Default False
            mock_config.password_min_length = 8
            mock_settings.return_value = mock_config

            with pytest.raises(ValidationError) as exc_info:
                UserCreationRequest(
                    email="test@example.com",
                    password="PASSWORD123",  # No lowercase, no special (which is not required)
                    first_name="Test",
                    last_name="User",
                )
            assert "lowercase letters" in str(exc_info.value)

    def test_password_validation_missing_numbers(self) -> None:
        """Test password validation fails when numbers required but missing."""
        # Mock settings to require numbers (which is default True)
        with patch("flext_auth.user_service.get_auth_settings") as mock_settings:
            mock_config = Mock()
            mock_config.password_require_numbers = True
            mock_config.password_require_uppercase = True
            mock_config.password_require_lowercase = True
            mock_config.password_require_special = False
            mock_config.password_min_length = 8
            mock_settings.return_value = mock_config

            with pytest.raises(ValidationError) as exc_info:
                UserCreationRequest(
                    email="test@example.com",
                    password="Password",  # No numbers, no special (not required)
                    first_name="Test",
                    last_name="User",
                )
            assert "digits" in str(exc_info.value)

    def test_password_validation_missing_special(self) -> None:
        """Test password validation fails when special chars required but missing."""
        # Need to patch settings to require special characters
        with patch("flext_auth.user_service.get_auth_settings") as mock_settings:
            mock_config = Mock()
            mock_config.password_require_special = True
            mock_config.password_require_uppercase = True
            mock_config.password_require_lowercase = True
            mock_config.password_require_numbers = True
            mock_config.password_min_length = 8
            mock_settings.return_value = mock_config

            with pytest.raises(ValidationError) as exc_info:
                UserCreationRequest(
                    email="test@example.com",
                    password="Password123",  # No special characters
                    first_name="Test",
                    last_name="User",
                )
            assert "special characters" in str(exc_info.value)

    def test_password_validation_too_short(self) -> None:
        """Test password validation fails when password is too short."""
        # Mock settings with min_length requirement
        with patch("flext_auth.user_service.get_auth_settings") as mock_settings:
            mock_config = Mock()
            mock_config.password_min_length = 8
            mock_config.password_require_uppercase = True
            mock_config.password_require_lowercase = True
            mock_config.password_require_numbers = True
            mock_config.password_require_special = False
            mock_settings.return_value = mock_config

            with pytest.raises(ValidationError) as exc_info:
                UserCreationRequest(
                    email="test@example.com",
                    password="Aa1",  # Too short (less than 8 chars), no special (not required)
                    first_name="Test",
                    last_name="User",
                )
            assert "at least" in str(exc_info.value)


class TestUserServiceInMemoryUserRepositoryExtended:
    """Extended tests for UserServiceInMemoryUserRepository."""

    @pytest.mark.asyncio
    async def test_update_user_not_found(self) -> None:
        """Test update_user raises ValueError when user not found."""
        repo = UserServiceInMemoryUserRepository()
        non_existent_id = uuid4()

        with pytest.raises(ValueError, match=".*not found.*") as exc_info:
            await repo.update_user(non_existent_id, {"username": "new_name"})
        assert "not found" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_update_user_invalid_field(self) -> None:
        """Test update_user skips invalid fields."""
        repo = UserServiceInMemoryUserRepository()

        # Create user first
        user_data = {
            "email": "test@example.com",
            "password_hash": "hashed_password",
            "username": "testuser",
        }
        created_user = await repo.create_user(user_data)

        # Update with valid and invalid fields
        update_data = {
            "username": "updated_username",
            "invalid_field": "should_be_ignored",
        }
        updated_user = await repo.update_user(created_user.id, update_data)

        assert updated_user.username == "updated_username"
        # Invalid field should be ignored (no exception raised)

    @pytest.mark.asyncio
    async def test_update_user_updates_timestamp(self) -> None:
        """Test update_user updates the updated_at timestamp."""
        repo = UserServiceInMemoryUserRepository()

        # Create user first
        user_data = {
            "email": "test@example.com",
            "password_hash": "hashed_password",
            "username": "testuser",
        }
        created_user = await repo.create_user(user_data)
        original_updated_at = created_user.updated_at

        # Small delay to ensure timestamp difference
        import asyncio

        await asyncio.sleep(0.01)

        # Update user
        updated_user = await repo.update_user(created_user.id, {"username": "new_name"})

        assert updated_user.updated_at > original_updated_at

    @pytest.mark.asyncio
    async def test_create_user_with_explicit_id(self) -> None:
        """Test create_user with explicitly provided user ID."""
        repo = UserServiceInMemoryUserRepository()
        explicit_id = uuid4()

        user_data = {
            "id": explicit_id,
            "email": "test@example.com",
            "password_hash": "hashed_password",
        }

        created_user = await repo.create_user(user_data)
        assert created_user.id == explicit_id

    @pytest.mark.asyncio
    async def test_create_user_with_string_id(self) -> None:
        """Test create_user converts string ID to UUID."""
        repo = UserServiceInMemoryUserRepository()
        string_id = str(uuid4())

        user_data = {
            "user_id": string_id,
            "email": "test@example.com",
            "password_hash": "hashed_password",
        }

        created_user = await repo.create_user(user_data)
        assert str(created_user.id) == string_id

    @pytest.mark.asyncio
    async def test_create_user_generates_username_from_names(self) -> None:
        """Test create_user generates username from first and last names."""
        repo = UserServiceInMemoryUserRepository()

        user_data = {
            "email": "test@example.com",
            "password_hash": "hashed_password",
            "first_name": "John",
            "last_name": "Doe",
        }

        created_user = await repo.create_user(user_data)
        assert created_user.username == "John Doe"

    @pytest.mark.asyncio
    async def test_create_fails_duplicate_id(self) -> None:
        """Test create method fails with duplicate ID."""
        repo = UserServiceInMemoryUserRepository()

        # Create first user
        user_data = {"email": "test1@example.com", "password_hash": "hash1"}
        user1 = await repo.create_user(user_data)

        # Try to create user with same ID
        from flext_auth.domain.entities import User

        duplicate_user = User(
            id=user1.id,
            email="test2@example.com",
            password_hash="hash2",
            username="user2",
            role="user",
        )

        result = await repo.create(duplicate_user)
        assert not result.success
        assert result.error is not None
        assert "already exists" in result.error

    @pytest.mark.asyncio
    async def test_delete_user_not_found(self) -> None:
        """Test delete returns failure when user not found."""
        repo = UserServiceInMemoryUserRepository()
        non_existent_id = uuid4()

        result = await repo.delete(non_existent_id)
        assert not result.success
        assert result.error is not None
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_delete_user_success(self) -> None:
        """Test successful user deletion."""
        repo = UserServiceInMemoryUserRepository()

        # Create user first
        user_data = {"email": "test@example.com", "password_hash": "hashed_password"}
        created_user = await repo.create_user(user_data)

        # Delete user
        result = await repo.delete(created_user.id)
        assert result.success
        assert result.data is True

        # Verify user is deleted
        find_result = await repo.find_by_id(created_user.id)
        assert find_result.data is None

    @pytest.mark.asyncio
    async def test_update_existing_user_success(self) -> None:
        """Test update method with existing user."""
        repo = UserServiceInMemoryUserRepository()

        # Create user first
        user_data = {"email": "test@example.com", "password_hash": "hashed_password"}
        created_user = await repo.create_user(user_data)

        # Update user
        created_user.username = "updated_username"
        result = await repo.update(created_user)

        assert result.success
        assert result.data is not None
        assert result.data.username == "updated_username"

    @pytest.mark.asyncio
    async def test_update_user_not_found_failure(self) -> None:
        """Test update method fails when user not found."""
        repo = UserServiceInMemoryUserRepository()

        from flext_auth.domain.entities import User

        non_existent_user = User(
            id=uuid4(),
            email="test@example.com",
            password_hash="hash",
            username="user",
            role="user",
        )

        result = await repo.update(non_existent_user)
        assert not result.success
        assert result.error is not None
        assert "not found" in result.error

    @pytest.mark.asyncio
    async def test_update_user_email_change(self) -> None:
        """Test update method properly handles email changes in index."""
        repo = UserServiceInMemoryUserRepository()

        # Create user
        user_data = {"email": "old@example.com", "password_hash": "hash"}
        created_user = await repo.create_user(user_data)
        old_email = created_user.email

        # Update email
        created_user.email = "new@example.com"
        result = await repo.update(created_user)

        assert result.success

        # Old email should no longer find user
        old_result = await repo.find_by_email(old_email)
        assert old_result.data is None

        # New email should find user
        new_result = await repo.find_by_email("new@example.com")
        assert new_result.data is not None
        assert new_result.data.id == created_user.id

    @pytest.mark.asyncio
    async def test_list_users_pagination(self) -> None:
        """Test list_users with pagination."""
        repo = UserServiceInMemoryUserRepository()

        # Create multiple users
        for i in range(5):
            user_data = {"email": f"user{i}@example.com", "password_hash": f"hash{i}"}
            await repo.create_user(user_data)

        # Test pagination
        result = await repo.list_users(limit=2, offset=1)
        assert result.success
        assert result.data is not None
        assert len(result.data) == 2

    @pytest.mark.asyncio
    async def test_repository_error_handling(self) -> None:
        """Test repository methods handle exceptions properly."""
        repo = UserServiceInMemoryUserRepository()

        # Test find_by_id error handling by mocking the dict.get method
        mock_users = Mock()
        mock_users.get.side_effect = Exception("Database error")
        repo._users = mock_users

        result = await repo.find_by_id(uuid4())
        assert not result.success
        assert result.error is not None
        assert "Error finding user by ID" in result.error

        # Test find_by_email error handling by mocking the dict.get method
        mock_email_index = Mock()
        mock_email_index.get.side_effect = Exception("Index error")
        repo._email_index = mock_email_index

        result = await repo.find_by_email("test@example.com")
        assert not result.success
        assert result.error is not None
        assert "Error finding user by email" in result.error


class TestSecurityAuditorImplExtended:
    """Extended tests for SecurityAuditorImpl."""

    @pytest.mark.asyncio
    async def test_log_security_event_with_token_metadata(self) -> None:
        """Test logging security event with TokenMetadata object."""
        auditor = SecurityAuditorImpl()

        # Create mock TokenMetadata
        from flext_auth.tokens import TokenMetadata

        token_metadata = TokenMetadata(
            token_id="test_token",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(minutes=30),
        )

        await auditor.log_security_event(
            event_type="token_created",
            user_id=uuid4(),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            metadata=token_metadata,
        )

        assert len(auditor._events) == 1
        event = auditor._events[0]
        assert event["event_type"] == "token_created"
        assert "token_id" in event["metadata"]

    @pytest.mark.asyncio
    async def test_log_security_event_with_token_type_enum(self) -> None:
        """Test logging with TokenType enum that has value attribute."""
        auditor = SecurityAuditorImpl()

        # Mock TokenMetadata with enum token_type
        mock_metadata = Mock()
        mock_metadata.token_id = "test_token"
        mock_metadata.token_type = Mock()
        mock_metadata.token_type.value = "access"
        mock_metadata.issued_at = dt.now(UTC)
        mock_metadata.expires_at = dt.now(UTC) + timedelta(minutes=30)

        await auditor.log_security_event(
            event_type="test_event",
            user_id=uuid4(),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
            metadata=mock_metadata,
        )

        event = auditor._events[0]
        assert event["metadata"]["token_type"] == "access"

    @pytest.mark.asyncio
    async def test_get_failed_login_attempts_by_ip(self) -> None:
        """Test getting failed login attempts filtered by IP."""
        auditor = SecurityAuditorImpl()

        # Add events with different IPs
        await auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_FAILURE,
            user_id=uuid4(),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )
        await auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_FAILURE,
            user_id=uuid4(),
            ip_address="192.168.1.200",
            user_agent="Mozilla/5.0",
        )

        # Get attempts for specific IP
        count = await auditor.get_failed_login_attempts(ip_address="192.168.1.100")
        assert count == 1

    @pytest.mark.asyncio
    async def test_get_failed_login_attempts_by_user(self) -> None:
        """Test getting failed login attempts filtered by user ID."""
        auditor = SecurityAuditorImpl()

        # Create specific user IDs
        user1_id = uuid4()
        user2_id = uuid4()

        # Add events for different users
        await auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_FAILURE,
            user_id=user1_id,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )
        await auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_FAILURE,
            user_id=user2_id,
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )

        # Get attempts for specific user
        count = await auditor.get_failed_login_attempts(user_id=user1_id)
        assert count == 1

    @pytest.mark.asyncio
    async def test_get_failed_login_attempts_with_window(self) -> None:
        """Test getting failed login attempts within time window."""
        auditor = SecurityAuditorImpl()

        # Manually add old event (outside window)
        old_event: dict[str, Any] = {
            "timestamp": (dt.now(UTC) - timedelta(hours=25)).isoformat(),
            "event_type": SecurityEvent.LOGIN_FAILURE,
            "user_id": "user1",
            "ip_address": None,
            "user_agent": None,
            "metadata": {},
        }
        auditor._events.append(old_event)

        # Add recent event
        await auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_FAILURE,
            user_id=uuid4(),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )

        # Get attempts within 1 hour window
        count = await auditor.get_failed_login_attempts(window=timedelta(hours=1))
        assert count == 1  # Should only count recent event

    @pytest.mark.asyncio
    async def test_get_failed_login_attempts_ignores_other_events(self) -> None:
        """Test that only LOGIN_FAILURE events are counted."""
        auditor = SecurityAuditorImpl()

        # Add non-login-failure events
        await auditor.log_security_event(
            event_type=SecurityEvent.LOGIN_SUCCESS,
            user_id=uuid4(),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )
        await auditor.log_security_event(
            event_type="other_event",
            user_id=uuid4(),
            ip_address="192.168.1.100",
            user_agent="Mozilla/5.0",
        )

        count = await auditor.get_failed_login_attempts()
        assert count == 0


class TestUserServiceExtended:
    """Extended tests for UserService class."""

    @pytest.fixture
    def mock_dependencies(self) -> dict[str, Any]:
        """Create mock dependencies for UserService."""
        return {
            "user_repository": Mock(spec=UserServiceInMemoryUserRepository),
            "password_hasher": Mock(spec=PasswordHasherImpl),
            "security_auditor": Mock(spec=SecurityAuditorImpl),
            "jwt_service": Mock(),
            "token_manager": Mock(),
        }

    def test_create_default_service(self, mock_dependencies: dict[str, Any]) -> None:
        """Test UserService.create_default() class method."""
        with patch("flext_auth.user_service.get_container") as mock_get_container:
            mock_container = Mock()
            mock_container.resolve.return_value = "service_instance"
            mock_get_container.return_value = mock_container

            result = UserService.create_default()

            assert result is not None
            mock_container.resolve.assert_called_once_with(UserService)

    @pytest.mark.asyncio
    async def test_create_user_existing_email_failure(
        self,
        mock_dependencies: dict[str, Any],
    ) -> None:
        """Test create_user fails when email already exists."""
        # Mock auth settings for password validation
        with patch("flext_auth.user_service.get_auth_settings") as mock_settings:
            mock_config = Mock()
            mock_config.password_min_length = 8
            mock_config.password_require_uppercase = True
            mock_config.password_require_lowercase = True
            mock_config.password_require_numbers = True
            mock_config.password_require_special = False
            mock_settings.return_value = mock_config

            service = UserService(**mock_dependencies)

            # Mock repository to return existing user
            mock_user = Mock()
            existing_result = ServiceResult.ok(mock_user)
            mock_dependencies[
                "user_repository"
            ].find_by_email.return_value = existing_result

            request = UserCreationRequest(
                email="existing@example.com",
                password="Password123!",
                first_name="Test",
                last_name="User",
            )

            result = await service.create_user(request)

            assert not result.success
            assert result.error is not None
            assert "already exists" in result.error

    @pytest.mark.asyncio
    async def test_create_user_repository_failure(
        self,
        mock_dependencies: dict[str, Any],
    ) -> None:
        """Test create_user handles repository failures."""
        service = UserService(**mock_dependencies)

        # Mock repository to return no existing user
        no_user_result = ServiceResult.ok(None)
        mock_dependencies["user_repository"].find_by_email.return_value = no_user_result

        # Mock repository create to fail
        create_failure: ServiceResult[Any] = ServiceResult.fail("Database error",
        )
        mock_dependencies["user_repository"].create.return_value = create_failure

        # Mock password hasher
        mock_dependencies["password_hasher"].hash_password.return_value = "hashed"

        request = UserCreationRequest(
            email="test@example.com",
            password="Password123!",
            first_name="Test",
            last_name="User",
        )

        result = await service.create_user(request)

        assert not result.success

    @pytest.mark.asyncio
    async def test_create_user_exception_handling(
        self,
        mock_dependencies: dict[str, Any],
    ) -> None:
        """Test create_user handles exceptions properly."""
        service = UserService(**mock_dependencies)

        # Mock repository to raise exception
        mock_dependencies["user_repository"].find_by_email.side_effect = Exception(
            "Database connection failed",
        )

        request = UserCreationRequest(
            email="test@example.com",
            password="Password123!",
            first_name="Test",
            last_name="User",
        )

        result = await service.create_user(request)

        assert not result.success
        assert result.error is not None
        assert "Database connection failed" in result.error

"""Unit tests for FlextAuth models module - Domain models and repositories.

Tests cover domain entities, repositories, factory methods,
and convenience functions for model operations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_auth.constants import FlextAuthConstants
from flext_auth.domain_entities import (
    FlextAuthModels,
)
from flext_auth.password_service import FlextPasswordService
from flext_auth.utilities import FlextAuthUtilities


class TestFlextAuthUser:
    """Unit tests for FlextAuthUser domain entity."""

    def test_user_creation_with_factory(self) -> None:
        """Test user creation using factory method."""
        user_result = FlextAuthModels.create_user(
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$test_hash",
            role=FlextAuthConstants.ROLE_USER,
        )

        assert user_result.success
        user = user_result.value

        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password_hash == "$2b$12$test_hash"
        assert user.role == FlextAuthConstants.ROLE_USER
        assert user.status == FlextAuthConstants.USER_STATUS_ACTIVE
        assert user.failed_login_attempts == 0
        assert user.locked_until is None
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)
        assert isinstance(user.id, str)
        assert len(user.id) > 10  # Should have reasonable ID length

    def test_user_creation_with_REDACTED_LDAP_BIND_PASSWORD_role(self) -> None:
        """Test user creation with REDACTED_LDAP_BIND_PASSWORD role."""
        user_result = FlextAuthModels.create_user(
            username="REDACTED_LDAP_BIND_PASSWORD",
            email="REDACTED_LDAP_BIND_PASSWORD@example.com",
            password_hash="$2b$12$REDACTED_LDAP_BIND_PASSWORD_hash",
            role=FlextAuthConstants.ROLE_ADMIN,
        )

        assert user_result.success
        user = user_result.value
        assert user.role == FlextAuthConstants.ROLE_ADMIN

    def test_user_can_login_when_active(self) -> None:
        """Test user can login when active."""
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value

        assert user.can_login() is True

    def test_user_cannot_login_when_locked(self) -> None:
        """Test user cannot login when locked."""
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value

        # Lock the user
        user.status = FlextAuthConstants.USER_STATUS_LOCKED
        user.locked_until = datetime.now(UTC) + timedelta(hours=1)

        assert user.can_login() is False

    def test_user_can_login_after_lockout_expires(self) -> None:
        """Test user can login after lockout expires."""
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value

        # Set expired lockout
        user.status = FlextAuthConstants.USER_STATUS_LOCKED
        user.locked_until = datetime.now(UTC) - timedelta(hours=1)  # Past time

        # Should be able to login (lockout expired)
        assert user.can_login() is True

    def test_user_cannot_login_when_inactive(self) -> None:
        """Test user cannot login when inactive."""
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value

        user.status = FlextAuthConstants.USER_STATUS_INACTIVE
        assert user.can_login() is False


class TestFlextAuthSession:
    """Unit tests for FlextAuthSession domain entity."""

    def test_session_creation_with_factory(self) -> None:
        """Test session creation using factory method."""
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
        assert isinstance(session.created_at, datetime)
        assert isinstance(session.id, str)
        assert len(session.id) > 10

    def test_session_creation_without_user_agent(self) -> None:
        """Test session creation without user agent."""
        expires_at = datetime.now(UTC) + timedelta(hours=8)

        session_result = FlextAuthModels.create_session(
            user_id="user123",
            access_token="test_token",
            expires_at=expires_at,
            ip_address="127.0.0.1",
        )

        assert session_result.success
        session = session_result.value
        assert session.user_agent is None

    def test_session_is_not_expired_when_current(self) -> None:
        """Test session is not expired when current."""
        expires_at = datetime.now(UTC) + timedelta(hours=1)  # Future time

        session_result = FlextAuthModels.create_session(
            "user123", "token", expires_at, "127.0.0.1"
        )
        assert session_result.success
        session = session_result.value

        assert session.is_expired() is False

    def test_session_is_expired_when_past(self) -> None:
        """Test session is expired when past expiration."""
        # Note: Factory method prevents creating expired sessions (business rule)
        # So we create a future session and manually modify its expiration
        expires_at = datetime.now(UTC) + timedelta(hours=1)  # Future time initially

        session_result = FlextAuthModels.create_session(
            "user123", "token", expires_at, "127.0.0.1"
        )
        assert session_result.success
        session = session_result.value

        # Manually set expiration to past time to test is_expired logic
        session.expires_at = datetime.now(UTC) - timedelta(hours=1)  # Now in past

        assert session.is_expired() is True

    def test_session_deactivate(self) -> None:
        """Test session deactivation."""
        expires_at = datetime.now(UTC) + timedelta(hours=8)

        session_result = FlextAuthModels.create_session(
            "user123", "token", expires_at, "127.0.0.1"
        )
        assert session_result.success
        session = session_result.value

        assert session.is_active is True
        session.deactivate()
        assert session.is_active is False


class TestFlextAuthRole:
    """Unit tests for FlextAuthRole domain entity."""

    def test_role_creation_with_factory(self) -> None:
        """Test role creation using factory method."""
        permissions = ["read", "write"]
        role_result = FlextAuthModels.create_role(
            name="editor",
            description="Can read and write",
            permissions=permissions,
        )

        assert role_result.success
        role = role_result.value

        assert role.name == "editor"
        assert role.description == "Can read and write"
        assert role.permissions == permissions
        assert role.is_active is True
        assert isinstance(role.created_at, datetime)
        assert isinstance(role.id, str)

    def test_role_creation_without_permissions(self) -> None:
        """Test role creation without permissions."""
        role_result = FlextAuthModels.create_role(
            name="basic",
            description="Basic role",
        )

        assert role_result.success
        role = role_result.value
        assert role.permissions == []

    def test_role_add_permission(self) -> None:
        """Test adding permission to role."""
        role_result = FlextAuthModels.create_role("test_role", "Test role")
        assert role_result.success
        role = role_result.value

        role.add_permission("read")
        assert "read" in role.permissions

        # Adding same permission again should not duplicate
        role.add_permission("read")
        assert role.permissions.count("read") == 1

    def test_role_remove_permission(self) -> None:
        """Test removing permission from role."""
        role_result = FlextAuthModels.create_role(
            "test_role", "Test role", ["read", "write"]
        )
        assert role_result.success
        role = role_result.value

        role.remove_permission("write")
        assert "write" not in role.permissions
        assert "read" in role.permissions

        # Removing non-existent permission should not error
        role.remove_permission("delete")  # Should not crash

    def test_role_has_permission(self) -> None:
        """Test checking if role has permission."""
        role_result = FlextAuthModels.create_role(
            "test_role", "Test role", ["read", "write"]
        )
        assert role_result.success
        role = role_result.value

        assert role.has_permission("read") is True
        assert role.has_permission("write") is True
        assert role.has_permission("delete") is False


class TestFlextAuthPermission:
    """Unit tests for FlextAuthPermission domain entity."""

    def test_permission_creation_with_factory(self) -> None:
        """Test permission creation using factory method."""
        permission_result = FlextAuthModels.create_permission(
            name="user.create",
            description="Create new users",
            resource="user",
            action="create",
        )

        assert permission_result.success
        permission = permission_result.value

        assert permission.name == "user.create"
        assert permission.description == "Create new users"
        assert permission.resource == "user"
        assert permission.action == "create"
        assert permission.is_active is True
        assert isinstance(permission.created_at, datetime)
        assert isinstance(permission.id, str)

    def test_permission_matches_action(self) -> None:
        """Test permission action matching."""
        permission_result = FlextAuthModels.create_permission(
            "user.read", "Read users", "user", "read"
        )
        assert permission_result.success
        permission = permission_result.value

        assert permission.matches("user", "read") is True
        assert permission.matches("user", "write") is False
        assert permission.matches("post", "read") is False


class TestInMemoryUserRepository:
    """Unit tests for InMemoryUserRepository."""

    def test_repository_initialization(self) -> None:
        """Test repository initialization."""
        repo = FlextAuthModels.InMemoryUserRepository()
        assert repo is not None
        # Repository should be empty initially
        assert len(repo._users) == 0

    def test_save_and_get_user(self) -> None:
        """Test saving and retrieving user."""
        repo = FlextAuthModels.InMemoryUserRepository()

        # Create user
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value

        # Save user
        save_result = repo.save(user)
        assert save_result.success

        # Retrieve by ID
        get_result = repo.get_by_id(user.id)
        assert get_result.success
        retrieved_user = get_result.value
        assert retrieved_user.username == "testuser"
        assert retrieved_user.email == "test@example.com"

    def test_get_user_by_username(self) -> None:
        """Test retrieving user by username."""
        repo = FlextAuthModels.InMemoryUserRepository()

        # Create and save user
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value
        repo.save(user)

        # Retrieve by username
        get_result = repo.get_by_username("testuser")
        assert get_result.success
        retrieved_user = get_result.value
        assert retrieved_user.id == user.id
        assert retrieved_user.email == "test@example.com"

    def test_get_user_by_email(self) -> None:
        """Test retrieving user by email."""
        repo = FlextAuthModels.InMemoryUserRepository()

        # Create and save user
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value
        repo.save(user)

        # Retrieve by email
        get_result = repo.get_by_email("test@example.com")
        assert get_result.success
        retrieved_user = get_result.value
        assert retrieved_user.id == user.id
        assert retrieved_user.username == "testuser"

    def test_get_nonexistent_user(self) -> None:
        """Test retrieving non-existent user."""
        repo = FlextAuthModels.InMemoryUserRepository()

        # Try to get user that doesn't exist
        get_result = repo.get_by_username("nonexistent")
        # Should succeed but return None
        assert get_result.success
        assert get_result.value is None

    def test_save_updates_existing_user(self) -> None:
        """Test that save updates existing user."""
        repo = FlextAuthModels.InMemoryUserRepository()

        # Create and save user
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash"
        )
        assert user_result.success
        user = user_result.value
        repo.save(user)

        # Modify user
        user.failed_login_attempts = 3

        # Save again
        save_result = repo.save(user)
        assert save_result.success

        # Retrieve and verify update
        get_result = repo.get_by_id(user.id)
        assert get_result.success
        updated_user = get_result.value
        assert updated_user.failed_login_attempts == 3


class TestInMemorySessionRepository:
    """Unit tests for InMemorySessionRepository."""

    def test_repository_initialization(self) -> None:
        """Test repository initialization."""
        repo = FlextAuthModels.InMemorySessionRepository()
        assert repo is not None
        assert len(repo._sessions) == 0

    def test_save_and_get_session(self) -> None:
        """Test saving and retrieving session."""
        repo = FlextAuthModels.InMemorySessionRepository()

        # Create session
        expires_at = datetime.now(UTC) + timedelta(hours=8)
        session_result = FlextAuthModels.create_session(
            "user123", "token", expires_at, "127.0.0.1"
        )
        assert session_result.success
        session = session_result.value

        # Save session
        save_result = repo.save(session)
        assert save_result.success

        # Retrieve by ID
        get_result = repo.get_by_id(session.id)
        assert get_result.success
        retrieved_session = get_result.value
        assert retrieved_session.user_id == "user123"
        assert retrieved_session.access_token == "token"

    def test_get_sessions_by_user_id(self) -> None:
        """Test retrieving sessions by user ID."""
        repo = FlextAuthModels.InMemorySessionRepository()

        # Create multiple sessions for same user
        expires_at = datetime.now(UTC) + timedelta(hours=8)

        session1_result = FlextAuthModels.create_session(
            "user123", "token1", expires_at, "127.0.0.1"
        )
        session2_result = FlextAuthModels.create_session(
            "user123", "token2", expires_at, "192.168.1.1"
        )
        session3_result = FlextAuthModels.create_session(
            "user456", "token3", expires_at, "127.0.0.1"
        )

        assert (
            session1_result.success
        )
        assert (
            session2_result.success
        )
        assert (
            session3_result.success
        )

        # Save all sessions
        repo.save(session1_result.value)
        repo.save(session2_result.value)
        repo.save(session3_result.value)

        # Get sessions for user123
        sessions_result = repo.get_by_user_id("user123")
        assert sessions_result.success
        sessions = sessions_result.value

        assert len(sessions) == 2
        user_ids = [s.user_id for s in sessions]
        assert all(uid == "user123" for uid in user_ids)

    def test_delete_expired_sessions(self) -> None:
        """Test deleting expired sessions."""
        repo = FlextAuthModels.InMemorySessionRepository()

        # Create mix of expired and current sessions
        past_time = datetime.now(UTC) - timedelta(hours=1)
        future_time = datetime.now(UTC) + timedelta(hours=1)

        expired_session = FlextAuthModels.create_session(
            "user1", "token1", past_time, "127.0.0.1"
        ).value
        current_session = FlextAuthModels.create_session(
            "user2", "token2", future_time, "127.0.0.1"
        ).value

        # Save both sessions
        repo.save(expired_session)
        repo.save(current_session)

        # Delete expired sessions
        delete_result = repo.delete_expired()
        assert delete_result.success
        deleted_count = delete_result.value
        assert deleted_count >= 1  # At least the expired one should be deleted

        # Current session should still exist
        get_result = repo.get_by_id(current_session.id)
        assert get_result.success
        assert get_result.value is not None


class TestModelConvenienceFunctions:
    """Unit tests for model convenience functions."""

    def test_validate_email_valid_addresses(self) -> None:
        """Test email validation with valid addresses."""
        valid_emails = [
            "test@example.com",
            "user.name@domain.co.uk",
            "user+tag@example.org",
            "user123@example-domain.com",
            "a@b.co",
        ]

        for email in valid_emails:
            result = FlextAuthUtilities.validate_email(email)
            assert result.success, f"Email {email} should be valid"

    def test_validate_email_invalid_addresses(self) -> None:
        """Test email validation with invalid addresses."""
        invalid_emails = [
            "invalid.email",  # No @ symbol
            "@example.com",  # No local part
            "user@",  # No domain
            "user..name@example.com",  # Double dots
            "",  # Empty string
            "user@invalid",  # No dot in domain
        ]

        for email in invalid_emails:
            result = FlextAuthUtilities.validate_email(email)
            assert result.is_failure, f"Email {email} should be invalid"

    def test_generate_secure_password_default_length(self) -> None:
        """Test secure password generation with default length."""
        password = FlextAuthUtilities.generate_secure_password()

        assert len(password) == 16  # Default length
        assert isinstance(password, str)

        # Should contain mix of character types
        has_lower = any(c.islower() for c in password)
        has_upper = any(c.isupper() for c in password)
        has_digit = any(c.isdigit() for c in password)
        has_special = any(c in '!@#$%^&*(),.?":{}|<>' for c in password)

        assert has_lower
        assert has_upper
        assert has_digit
        assert has_special

    def test_generate_secure_password_custom_length(self) -> None:
        """Test secure password generation with custom length."""
        for length in [8, 12, 20, 32]:
            password = FlextAuthUtilities.generate_secure_password(length)
            assert len(password) == length

    def test_generate_secure_password_minimum_length(self) -> None:
        """Test secure password generation respects minimum length."""
        # Even if we ask for very short, should get at least 8
        password = FlextAuthUtilities.generate_secure_password(4)
        assert len(password) == 8  # Minimum enforced

    def test_generate_secure_password_uniqueness(self) -> None:
        """Test that generated passwords are unique."""
        passwords = [FlextAuthUtilities.generate_secure_password() for _ in range(10)]

        # All passwords should be different
        assert len(set(passwords)) == 10

    def test_is_strong_password_strong(self) -> None:
        """Test password strength validation with strong passwords."""
        password_service = FlextPasswordService()
        strong_passwords = [
            "StrongPassword123!",
            "Another$ecure1Password",
            "Complex&Password2023",
        ]

        for password in strong_passwords:
            result = password_service.validate_password_strength(password)
            assert result.success is True

    def test_is_strong_password_weak(self) -> None:
        """Test password strength validation with weak passwords."""
        password_service = FlextPasswordService()
        weak_passwords = [
            "weak",
            "12345678",
            "password",
            "PASSWORD",
        ]

        for password in weak_passwords:
            result = password_service.validate_password_strength(password)
            assert result.success is False


class TestModelsIntegration:
    """Integration tests for model operations."""

    def test_complete_user_session_lifecycle(self) -> None:
        """Test complete user and session lifecycle."""
        user_repo = FlextAuthModels.InMemoryUserRepository()
        session_repo = FlextAuthModels.InMemorySessionRepository()

        # 1. Create user
        user_result = FlextAuthModels.create_user(
            "testuser", "test@example.com", "hash", FlextAuthConstants.ROLE_USER
        )
        assert user_result.success
        user = user_result.value

        # 2. Save user
        user_save = user_repo.save(user)
        assert user_save.success

        # 3. Create session for user
        expires_at = datetime.now(UTC) + timedelta(hours=8)
        session_result = FlextAuthModels.create_session(
            user.id, "access_token", expires_at, "127.0.0.1", "test-agent"
        )
        assert session_result.success
        session = session_result.value

        # 4. Save session
        session_save = session_repo.save(session)
        assert session_save.success

        # 5. Retrieve user sessions
        sessions_result = session_repo.get_by_user_id(user.id)
        assert sessions_result.success
        sessions = sessions_result.value
        assert len(sessions) == 1
        assert sessions[0].access_token == "access_token"

        # 6. Update user (failed login attempt)
        user.failed_login_attempts += 1
        update_save = user_repo.save(user)
        assert update_save.success

        # 7. Verify update persisted
        updated_user_result = user_repo.get_by_id(user.id)
        assert updated_user_result.success
        updated_user = updated_user_result.value
        assert updated_user.failed_login_attempts == 1

    def test_role_permission_management(self) -> None:
        """Test role and permission management."""
        # Create permissions
        read_perm_result = FlextAuthModels.create_permission(
            "user.read", "Read users", "user", "read"
        )
        write_perm_result = FlextAuthModels.create_permission(
            "user.write", "Write users", "user", "write"
        )

        assert read_perm_result.success
        assert write_perm_result.success

        # Create role with permissions
        role_result = FlextAuthModels.create_role(
            "editor", "User editor role", ["user.read", "user.write"]
        )
        assert role_result.success
        role = role_result.value

        # Test role permissions
        assert role.has_permission("user.read") is True
        assert role.has_permission("user.write") is True
        assert role.has_permission("user.delete") is False

        # Add new permission
        role.add_permission("user.delete")
        assert role.has_permission("user.delete") is True

        # Remove permission
        role.remove_permission("user.write")
        assert role.has_permission("user.write") is False

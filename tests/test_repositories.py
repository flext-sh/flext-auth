"""Comprehensive tests for repository implementations.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from flext_auth import (
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
    InMemorySessionRepository,
    InMemoryUserRepository,
)

# Constants
EXPECTED_BULK_SIZE = 2
EXPECTED_DATA_COUNT = 3


@pytest.fixture
def user_repository() -> InMemoryUserRepository:
    """Create in-memory user repository for testing."""
    return InMemoryUserRepository()


@pytest.fixture
def session_repository() -> InMemorySessionRepository:
    """Create in-memory session repository for testing."""
    return InMemorySessionRepository()


@pytest.fixture
def sample_user() -> FlextUser:
    """Create sample user for testing."""
    return FlextUser(
        id="user-123",
        username="testuser",
        email="test@example.com",
        password_hash="$2b$12$hashedpassword",
        role=FlextUserRole.USER,
        status=FlextUserStatus.ACTIVE,
    )


@pytest.fixture
def sample_session() -> FlextSession:
    """Create sample session for testing."""
    return FlextSession(
        id="session-123",
        user_id="user-123",
        access_token="access-token-value",
        refresh_token="refresh-token-value",
        status=FlextSessionStatus.ACTIVE,
        ip_address="192.168.1.1",
        user_agent="Test Browser",
        expires_at=datetime.now(UTC) + timedelta(hours=24),
    )


class TestUserRepository:
    """Test user repository functionality."""

    async def test_save_user_success(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test successful user saving."""
        result = await user_repository.save(sample_user)

        assert result.success
        if result.data.id != sample_user.id:
            msg: str = f"Expected {sample_user.id}, got {result.data.id}"
            raise AssertionError(msg)
        assert result.data.username == sample_user.username

    async def test_save_user_duplicate_username(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test saving user with duplicate username."""
        # Save first user
        result1 = await user_repository.save(sample_user)
        assert result1.success

        # Try to save another user with same username
        duplicate_user = FlextUser(
            id="different-id",
            username=sample_user.username,  # Same username
            email="different@example.com",
            password_hash="$2b$12$differenthash",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        result2 = await user_repository.save(duplicate_user)
        assert not result2.success
        if "already exists" not in result2.error:
            msg: str = f"Expected {'already exists'} in {result2.error}"
            raise AssertionError(msg)

    async def test_save_user_duplicate_email(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test saving user with duplicate email."""
        # Save first user
        result1 = await user_repository.save(sample_user)
        assert result1.success

        # Try to save another user with same email
        duplicate_user = FlextUser(
            id="different-id",
            username="differentuser",
            email=sample_user.email,  # Same email
            password_hash="$2b$12$differenthash",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        result2 = await user_repository.save(duplicate_user)
        assert not result2.success
        if "already exists" not in result2.error:
            msg: str = f"Expected {'already exists'} in {result2.error}"
            raise AssertionError(msg)

    async def test_save_user_update_existing(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test updating existing user."""
        # Save user
        result1 = await user_repository.save(sample_user)
        assert result1.success

        # Update user (create new instance since entities are immutable)
        updated_user = FlextUser(
            id=sample_user.id,
            username=sample_user.username,
            email=sample_user.email,
            password_hash=sample_user.password_hash,
            role=sample_user.role,
            status=FlextUserStatus.INACTIVE,
        )
        result2 = await user_repository.save(updated_user)
        assert result2.success
        if result2.data.status != FlextUserStatus.INACTIVE:
            msg: str = f"Expected {FlextUserStatus.INACTIVE}, got {result2.data.status}"
            raise AssertionError(msg)

    async def test_get_user_by_id_success(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test successful user retrieval by ID."""
        # Save user
        await user_repository.save(sample_user)

        # Get user by ID
        result = await user_repository.get_by_id(sample_user.id)
        assert result.success
        assert result.data is not None
        if result.data.id != sample_user.id:
            msg: str = f"Expected {sample_user.id}, got {result.data.id}"
            raise AssertionError(msg)
        assert result.data.username == sample_user.username

    async def test_get_user_by_id_not_found(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test user retrieval with non-existent ID."""
        result = await user_repository.get_by_id("non-existent")
        assert result.success
        assert result.data is None

    async def test_get_user_by_username_success(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test successful user retrieval by username."""
        # Save user
        await user_repository.save(sample_user)

        # Get user by username
        result = await user_repository.get_by_username(sample_user.username)
        assert result.success
        assert result.data is not None
        if result.data.username != sample_user.username:
            msg: str = f"Expected {sample_user.username}, got {result.data.username}"
            raise AssertionError(msg)

    async def test_get_user_by_username_case_insensitive(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test case-insensitive username lookup."""
        # Save user
        await user_repository.save(sample_user)

        # Get user with different case
        result = await user_repository.get_by_username(sample_user.username.upper())
        assert result.success
        assert result.data is not None
        if result.data.username != sample_user.username:
            msg: str = f"Expected {sample_user.username}, got {result.data.username}"
            raise AssertionError(msg)

    async def test_get_user_by_username_not_found(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test user retrieval with non-existent username."""
        result = await user_repository.get_by_username("nonexistent")
        assert result.success
        assert result.data is None

    async def test_get_user_by_email_success(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test successful user retrieval by email."""
        # Save user
        await user_repository.save(sample_user)

        # Get user by email
        result = await user_repository.get_by_email(str(sample_user.email))
        assert result.success
        assert result.data is not None
        if str(result.data.email) != str(sample_user.email):
            msg: str = f"Expected {sample_user.email!s}, got {result.data.email!s}"
            raise AssertionError(msg)

    async def test_get_user_by_email_case_insensitive(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test case-insensitive email lookup."""
        # Save user
        await user_repository.save(sample_user)

        # Get user with different case
        result = await user_repository.get_by_email(str(sample_user.email).upper())
        assert result.success
        assert result.data is not None
        if str(result.data.email) != str(sample_user.email):
            msg: str = f"Expected {sample_user.email!s}, got {result.data.email!s}"
            raise AssertionError(msg)

    async def test_get_user_by_email_not_found(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test user retrieval with non-existent email."""
        result = await user_repository.get_by_email("nonexistent@example.com")
        assert result.success
        assert result.data is None

    async def test_delete_user_success(
        self,
        user_repository: InMemoryUserRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test successful user deletion."""
        # Save user
        await user_repository.save(sample_user)

        # Delete user
        result = await user_repository.delete(sample_user.id)
        assert result.success
        if not (result.data):
            msg: str = f"Expected True, got {result.data}"
            raise AssertionError(msg)

        # Verify user is gone
        get_result = await user_repository.get_by_id(sample_user.id)
        assert get_result.success
        assert get_result.data is None

    async def test_delete_user_not_found(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test deletion of non-existent user."""
        result = await user_repository.delete("non-existent")
        assert result.success
        if result.data:
            msg: str = f"Expected False, got {result.data}"
            raise AssertionError(msg)

    async def test_list_users_no_filter(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test listing users without filters."""
        # Create and save multiple users
        users = []
        for i in range(5):
            user = FlextUser(
                id=f"user-{i}",
                username=f"user{i}",
                email=f"user{i}@example.com",
                password_hash="$2b$12$hash",
                role=FlextUserRole.USER,
                status=FlextUserStatus.ACTIVE
                if i % 2 == 0
                else FlextUserStatus.INACTIVE,
            )
            users.append(user)
            await user_repository.save(user)

        # List all users
        result = await user_repository.list_users()
        assert result.success
        if len(result.data) != 5:
            msg: str = f"Expected {5}, got {len(result.data)}"
            raise AssertionError(msg)

        # Should be sorted by created_at (newest first)
        sorted_users = result.data
        for i in range(len(sorted_users) - 1):
            if sorted_users[i].created_at < sorted_users[i + 1].created_at:
                msg: str = f"Expected {sorted_users[i].created_at} >= {sorted_users[i + 1].created_at}"
                raise AssertionError(msg)

    async def test_list_users_with_status_filter(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test listing users with status filter."""
        # Create users with different statuses
        active_users = []
        inactive_users = []

        for i in range(3):
            active_user = FlextUser(
                id=f"active-{i}",
                username=f"active{i}",
                email=f"active{i}@example.com",
                password_hash="$2b$12$hash",
                role=FlextUserRole.USER,
                status=FlextUserStatus.ACTIVE,
            )
            active_users.append(active_user)
            await user_repository.save(active_user)

            inactive_user = FlextUser(
                id=f"inactive-{i}",
                username=f"inactive{i}",
                email=f"inactive{i}@example.com",
                password_hash="$2b$12$hash",
                role=FlextUserRole.USER,
                status=FlextUserStatus.INACTIVE,
            )
            inactive_users.append(inactive_user)
            await user_repository.save(inactive_user)

        # List active users
        active_result = await user_repository.list_users(status=FlextUserStatus.ACTIVE)
        assert active_result.success
        if len(active_result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(active_result.data)}"
            raise AssertionError(msg)
        if not all(u.status == FlextUserStatus.ACTIVE for u in active_result.data):
            msg: str = f"Expected all users to be ACTIVE in {active_result.data}"
            raise AssertionError(msg)

        # List inactive users
        inactive_result = await user_repository.list_users(
            status=FlextUserStatus.INACTIVE,
        )
        assert inactive_result.success
        if len(inactive_result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(inactive_result.data)}"
            raise AssertionError(msg)
        if not all(u.status == FlextUserStatus.INACTIVE for u in inactive_result.data):
            msg: str = f"Expected all users to be INACTIVE in {inactive_result.data}"
            raise AssertionError(msg)

    async def test_list_users_pagination(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test user listing with pagination."""
        # Create 10 users
        for i in range(10):
            user = FlextUser(
                id=f"user-{i}",
                username=f"user{i}",
                email=f"user{i}@example.com",
                password_hash="$2b$12$hash",
                role=FlextUserRole.USER,
                status=FlextUserStatus.ACTIVE,
            )
            await user_repository.save(user)

        # Get first page
        page1 = await user_repository.list_users(limit=3, offset=0)
        assert page1.success
        if len(page1.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(page1.data)}"
            raise AssertionError(msg)

        # Get second page
        page2 = await user_repository.list_users(limit=3, offset=3)
        assert page2.success
        if len(page2.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(page2.data)}"
            raise AssertionError(msg)

        # Pages should not overlap
        page1_ids = {u.id for u in page1.data}
        page2_ids = {u.id for u in page2.data}
        assert page1_ids.isdisjoint(page2_ids)

    async def test_count_users_no_filter(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test counting users without filter."""
        # Create users
        for i in range(5):
            user = FlextUser(
                id=f"user-{i}",
                username=f"user{i}",
                email=f"user{i}@example.com",
                password_hash="$2b$12$hash",
                role=FlextUserRole.USER,
                status=FlextUserStatus.ACTIVE,
            )
            await user_repository.save(user)

        result = await user_repository.count_users()
        assert result.success
        if result.data != 5:
            msg: str = f"Expected {5}, got {result.data}"
            raise AssertionError(msg)

    async def test_count_users_with_status_filter(
        self,
        user_repository: InMemoryUserRepository,
    ) -> None:
        """Test counting users with status filter."""
        # Create users with different statuses
        for i in range(3):
            active_user = FlextUser(
                id=f"active-{i}",
                username=f"active{i}",
                email=f"active{i}@example.com",
                password_hash="$2b$12$hash",
                role=FlextUserRole.USER,
                status=FlextUserStatus.ACTIVE,
            )
            await user_repository.save(active_user)

        for i in range(2):
            inactive_user = FlextUser(
                id=f"inactive-{i}",
                username=f"inactive{i}",
                email=f"inactive{i}@example.com",
                password_hash="$2b$12$hash",
                role=FlextUserRole.USER,
                status=FlextUserStatus.INACTIVE,
            )
            await user_repository.save(inactive_user)

        # Count active users
        active_count = await user_repository.count_users(status=FlextUserStatus.ACTIVE)
        assert active_count.success
        if active_count.data != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {active_count.data}"
            raise AssertionError(msg)

        # Count inactive users
        inactive_count = await user_repository.count_users(
            status=FlextUserStatus.INACTIVE,
        )
        assert inactive_count.success
        if inactive_count.data != EXPECTED_BULK_SIZE:
            msg: str = f"Expected {2}, got {inactive_count.data}"
            raise AssertionError(msg)


class TestSessionRepository:
    """Test session repository functionality."""

    async def test_save_session_success(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None:
        """Test successful session saving."""
        result = await session_repository.save(sample_session)

        assert result.success
        if result.data.id != sample_session.id:
            msg: str = f"Expected {sample_session.id}, got {result.data.id}"
            raise AssertionError(msg)
        assert result.data.user_id == sample_session.user_id

    async def test_save_session_preserves_data(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None:
        """Test that saving preserves session data (entities are immutable)."""
        result = await session_repository.save(sample_session)
        assert result.success

        # Session data should be preserved exactly
        if result.data.id != sample_session.id:
            msg: str = f"Expected {sample_session.id}, got {result.data.id}"
            raise AssertionError(msg)
        assert result.data.user_id == sample_session.user_id
        if result.data.access_token != sample_session.access_token:
            msg: str = f"Expected {sample_session.access_token}, got {result.data.access_token}"
            raise AssertionError(msg)
        assert result.data.last_accessed == sample_session.last_accessed

    async def test_save_session_update_existing(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None:
        """Test updating existing session."""
        # Save session
        result1 = await session_repository.save(sample_session)
        assert result1.success

        # Create updated session (entities are immutable)
        updated_session = FlextSession(
            id=sample_session.id,
            user_id=sample_session.user_id,
            access_token=sample_session.access_token,
            refresh_token=sample_session.refresh_token,
            expires_at=sample_session.expires_at,
            ip_address=sample_session.ip_address,
            user_agent=sample_session.user_agent,
            status=FlextSessionStatus.REVOKED,
        )
        result2 = await session_repository.save(updated_session)
        assert result2.success
        if result2.data.status != FlextSessionStatus.REVOKED:
            msg: str = (
                f"Expected {FlextSessionStatus.REVOKED}, got {result2.data.status}"
            )
            raise AssertionError(msg)

    async def test_get_session_by_id_success(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None:
        """Test successful session retrieval by ID."""
        # Save session
        await session_repository.save(sample_session)

        # Get session by ID
        result = await session_repository.get_by_id(sample_session.id)
        assert result.success
        assert result.data is not None
        if result.data.id != sample_session.id:
            msg: str = f"Expected {sample_session.id}, got {result.data.id}"
            raise AssertionError(msg)

    async def test_get_session_by_id_not_found(
        self,
        session_repository: InMemorySessionRepository,
    ) -> None:
        """Test session retrieval with non-existent ID."""
        result = await session_repository.get_by_id("non-existent")
        assert result.success
        assert result.data is None

    async def test_get_sessions_by_user_id(
        self,
        session_repository: InMemorySessionRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test getting sessions by user ID."""
        # Create multiple sessions for user
        sessions = []
        for i in range(3):
            session = FlextSession(
                id=f"session-{i}",
                user_id=str(sample_user.id),
                access_token=f"token-{i}",
                status=FlextSessionStatus.ACTIVE,
                ip_address="192.168.1.1",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
            sessions.append(session)
            await session_repository.save(session)

        # Get sessions by user ID
        result = await session_repository.get_by_user_id(sample_user.id)
        assert result.success
        if len(result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(result.data)}"
            raise AssertionError(msg)

    async def test_get_sessions_by_user_id_not_found(
        self,
        session_repository: InMemorySessionRepository,
    ) -> None:
        """Test getting sessions for non-existent user."""
        result = await session_repository.get_by_user_id("non-existent-user")
        assert result.success
        if len(result.data) != 0:
            msg: str = f"Expected {0}, got {len(result.data)}"
            raise AssertionError(msg)

    async def test_get_active_sessions(
        self,
        session_repository: InMemorySessionRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test getting only active sessions."""
        # Create active session
        active_session = FlextSession(
            id="active-session",
            user_id=str(sample_user.id),
            access_token="active-token",
            status=FlextSessionStatus.ACTIVE,
            ip_address="192.168.1.1",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        await session_repository.save(active_session)

        # Create revoked session
        revoked_session = FlextSession(
            id="revoked-session",
            user_id=str(sample_user.id),
            access_token="revoked-token",
            status=FlextSessionStatus.REVOKED,
            ip_address="192.168.1.1",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        await session_repository.save(revoked_session)

        # Create expired session
        expired_session = FlextSession(
            id="expired-session",
            user_id=str(sample_user.id),
            access_token="expired-token",
            status=FlextSessionStatus.ACTIVE,
            ip_address="192.168.1.1",
            expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
        )
        await session_repository.save(expired_session)

        # Get active sessions
        result = session_repository.get_active_session_count(str(sample_user.id))
        assert result.success
        if result.data != 1:
            msg: str = f"Expected {1}, got {result.data}"
            raise AssertionError(msg)

    async def test_revoke_session(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None:
        """Test session revocation."""
        # Save active session
        await session_repository.save(sample_session)

        # Revoke session
        result = await session_repository.revoke_session(sample_session.id)
        assert result.success
        if not (result.data):
            msg: str = f"Expected True, got {result.data}"
            raise AssertionError(msg)

        # Verify session is revoked (no longer accessible)
        session_result = await session_repository.get_by_id(sample_session.id)
        assert session_result.success
        if session_result.data is not None:
            msg: str = f"Expected None (revoked session), got {session_result.data}"
            raise AssertionError(msg)

    async def test_revoke_session_not_found(
        self,
        session_repository: InMemorySessionRepository,
    ) -> None:
        """Test revoking non-existent session."""
        result = await session_repository.revoke_session("non-existent")
        assert result.success
        if result.data:
            msg: str = f"Expected False, got {result.data}"
            raise AssertionError(msg)

    async def test_revoke_all_user_sessions(
        self,
        session_repository: InMemorySessionRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test revoking all sessions for a user."""
        # Create multiple active sessions
        active_sessions = []
        for i in range(3):
            session = FlextSession(
                id=f"session-{i}",
                user_id=str(sample_user.id),
                access_token=f"token-{i}",
                status=FlextSessionStatus.ACTIVE,
                ip_address="192.168.1.1",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
            active_sessions.append(session)
            await session_repository.save(session)

        # Create already revoked session
        revoked_session = FlextSession(
            id="revoked-session",
            user_id=str(sample_user.id),
            access_token="revoked-token",
            status=FlextSessionStatus.REVOKED,
            ip_address="192.168.1.1",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        await session_repository.save(revoked_session)

        # Revoke all user sessions
        result = await session_repository.revoke_all_user_sessions(sample_user.id)
        assert result.success
        # Only 3 active sessions were revoked
        if result.data != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {EXPECTED_DATA_COUNT} (only active sessions), got {result.data}"
            raise AssertionError(msg)

        # Verify all sessions are now revoked
        all_sessions_result = await session_repository.get_by_user_id(sample_user.id)
        assert all_sessions_result.success

        for session in all_sessions_result.data:
            if session.status != FlextSessionStatus.REVOKED:
                msg: str = (
                    f"Expected {FlextSessionStatus.REVOKED}, got {session.status}"
                )
                raise AssertionError(msg)

    async def test_cleanup_expired_sessions(
        self,
        session_repository: InMemorySessionRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test cleanup of expired sessions."""
        # Create expired sessions
        for i in range(2):
            expired_session = FlextSession(
                id=f"expired-{i}",
                user_id=str(sample_user.id),
                access_token=f"expired-token-{i}",
                status=FlextSessionStatus.ACTIVE,
                ip_address="192.168.1.1",
                expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
            )
            await session_repository.save(expired_session)

        # Create non-expired session
        active_session = FlextSession(
            id="active-session",
            user_id=str(sample_user.id),
            access_token="active-token",
            status=FlextSessionStatus.ACTIVE,
            ip_address="192.168.1.1",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        await session_repository.save(active_session)

        # Cleanup expired sessions
        result = session_repository.cleanup_expired_sessions()
        assert result.success
        if result.data != EXPECTED_BULK_SIZE:  # 2 expired sessions cleaned:
            msg: str = f"Expected {2}, got {result.data}"
            raise AssertionError(msg)

        # Verify expired sessions are gone
        expired1_result = await session_repository.get_by_id("expired-0")
        assert expired1_result.success
        assert expired1_result.data is None

        expired2_result = await session_repository.get_by_id("expired-1")
        assert expired2_result.success
        assert expired2_result.data is None

        # Verify active session remains
        active_result = await session_repository.get_by_id("active-session")
        assert active_result.success
        assert active_result.data is not None

    async def test_delete_session(
        self,
        session_repository: InMemorySessionRepository,
        sample_session: FlextSession,
    ) -> None:
        """Test session deletion."""
        # Save session
        await session_repository.save(sample_session)

        # Delete session
        result = await session_repository.revoke_session(sample_session.id)
        assert result.success
        if not (result.data):
            msg: str = f"Expected True, got {result.data}"
            raise AssertionError(msg)

        # Verify session is gone
        get_result = await session_repository.get_by_id(sample_session.id)
        assert get_result.success
        assert get_result.data is None

    async def test_delete_session_not_found(
        self,
        session_repository: InMemorySessionRepository,
    ) -> None:
        """Test deletion of non-existent session."""
        result = await session_repository.revoke_session("non-existent")
        assert result.success
        if result.data:
            msg: str = f"Expected False, got {result.data}"
            raise AssertionError(msg)

    async def test_session_user_index_consistency(
        self,
        session_repository: InMemorySessionRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test that user-session index remains consistent."""
        # Create sessions
        sessions = []
        for i in range(3):
            session = FlextSession(
                id=f"session-{i}",
                user_id=str(sample_user.id),
                access_token=f"token-{i}",
                status=FlextSessionStatus.ACTIVE,
                ip_address="192.168.1.1",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
            sessions.append(session)
            await session_repository.save(session)

        # Verify all sessions are indexed
        user_sessions_result = await session_repository.get_by_user_id(sample_user.id)
        assert user_sessions_result.success
        if len(user_sessions_result.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(user_sessions_result.data)}"
            raise AssertionError(msg)

        # Delete one session
        await session_repository.revoke_session(sessions[0].id)

        # Verify index is updated
        user_sessions_result = await session_repository.get_by_user_id(sample_user.id)
        assert user_sessions_result.success
        if len(user_sessions_result.data) != EXPECTED_BULK_SIZE:
            msg: str = f"Expected {2}, got {len(user_sessions_result.data)}"
            raise AssertionError(msg)

        # Verify correct sessions remain
        remaining_ids = {s.id for s in user_sessions_result.data}
        expected_ids = {sessions[1].id, sessions[2].id}
        if remaining_ids != expected_ids:
            msg: str = f"Expected {expected_ids}, got {remaining_ids}"
            raise AssertionError(msg)


class TestRepositoryIntegration:
    """Integration tests for repository interactions."""

    async def test_user_session_relationship(
        self,
        user_repository: InMemoryUserRepository,
        session_repository: InMemorySessionRepository,
        sample_user: FlextUser,
    ) -> None:
        """Test relationship between users and sessions."""
        # Save user
        await user_repository.save(sample_user)

        # Create sessions for user
        sessions = []
        for i in range(3):
            session = FlextSession(
                id=f"session-{i}",
                user_id=str(sample_user.id),
                access_token=f"token-{i}",
                status=FlextSessionStatus.ACTIVE,
                ip_address="192.168.1.1",
                expires_at=datetime.now(UTC) + timedelta(hours=1),
            )
            sessions.append(session)
            await session_repository.save(session)

        # Get user sessions
        user_sessions = await session_repository.get_by_user_id(sample_user.id)
        assert user_sessions.success
        if len(user_sessions.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(user_sessions.data)}"
            raise AssertionError(msg)

        # Delete user but keep sessions (orphaned sessions)
        await user_repository.delete(sample_user.id)

        # Sessions should still exist (repository doesn't enforce FK constraints)
        user_sessions = await session_repository.get_by_user_id(sample_user.id)
        assert user_sessions.success
        if len(user_sessions.data) != EXPECTED_DATA_COUNT:
            msg: str = f"Expected {3}, got {len(user_sessions.data)}"
            raise AssertionError(msg)

    async def test_repository_error_handling(
        self,
        user_repository: InMemoryUserRepository,
        session_repository: InMemorySessionRepository,
    ) -> None:
        """Test repository error handling scenarios."""
        # Test with None values (should be handled gracefully)
        user_result = await user_repository.get_by_id("")
        assert user_result.success
        assert user_result.data is None

        session_result = await session_repository.get_by_id("")
        assert session_result.success
        assert session_result.data is None

        # Test with invalid data types (should be handled by entity validation)
        # These tests verify the repository doesn't crash on edge cases

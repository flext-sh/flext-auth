"""Test domain entities following flext-core patterns."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from flext_auth.domain.entities import (
    FlextPermission,
    FlextRole,
    FlextSession,
    FlextSessionStatus,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
)


class TestFlextUser:
    """Test FlextUser entity."""

    def test_user_creation(self) -> None:
        """Test user entity creation."""
        user = FlextUser(
            id="test-user-id",
            username="testuser",
            email="test@example.com",
            password_hash="$2b$12$test.hash",
            role=FlextUserRole.USER,
            status=FlextUserStatus.ACTIVE,
        )

        assert user.id == "test-user-id"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.role == FlextUserRole.USER
        assert user.status == FlextUserStatus.ACTIVE

    def test_user_is_active(self) -> None:
        """Test user is_active method."""
        user = FlextUser(
            id="test-id",
            username="test",
            email="test@example.com",
            password_hash="hash",
            status=FlextUserStatus.ACTIVE,
        )
        assert user.is_active() is True

        user_inactive = FlextUser(
            id="test-id",
            username="test",
            email="test@example.com",
            password_hash="hash",
            status=FlextUserStatus.INACTIVE,
        )
        assert user_inactive.is_active() is False

    def test_user_is_locked(self) -> None:
        """Test user is_locked method."""
        user_locked = FlextUser(
            id="test-id",
            username="test",
            email="test@example.com",
            password_hash="hash",
            status=FlextUserStatus.LOCKED,
        )
        assert user_locked.is_locked() is True

        future_time = datetime.now(UTC) + timedelta(hours=1)
        user_temp_locked = FlextUser(
            id="test-id",
            username="test",
            email="test@example.com",
            password_hash="hash",
            locked_until=future_time,
        )
        assert user_temp_locked.is_locked() is True

    def test_user_is_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test user is_REDACTED_LDAP_BIND_PASSWORD method."""
        REDACTED_LDAP_BIND_PASSWORD_user = FlextUser(
            id="test-id",
            username="REDACTED_LDAP_BIND_PASSWORD",
            email="REDACTED_LDAP_BIND_PASSWORD@example.com",
            password_hash="hash",
            role=FlextUserRole.ADMIN,
        )
        assert REDACTED_LDAP_BIND_PASSWORD_user.is_REDACTED_LDAP_BIND_PASSWORD() is True

        regular_user = FlextUser(
            id="test-id",
            username="user",
            email="user@example.com",
            password_hash="hash",
            role=FlextUserRole.USER,
        )
        assert regular_user.is_REDACTED_LDAP_BIND_PASSWORD() is False

    def test_user_validate_domain_rules(self) -> None:
        """Test user domain rules validation."""
        valid_user = FlextUser(
            id="test-id",
            username="validuser",
            email="valid@example.com",
            password_hash="valid-hash",
        )
        # Should not raise
        valid_user.validate_domain_rules()

        # Test short username
        with pytest.raises(ValueError, match="Username must be at least 3 characters"):
            FlextUser(
                id="test-id",
                username="ab",
                email="test@example.com",
                password_hash="hash",
            ).validate_domain_rules()

        # Test long username
        with pytest.raises(ValueError, match="Username must be at most 50 characters"):
            FlextUser(
                id="test-id",
                username="a" * 51,
                email="test@example.com",
                password_hash="hash",
            ).validate_domain_rules()

        # Test invalid email
        with pytest.raises(ValueError, match="Email must contain @ symbol"):
            FlextUser(
                id="test-id",
                username="user",
                email="invalid-email",
                password_hash="hash",
            ).validate_domain_rules()

        # Test empty password hash
        with pytest.raises(ValueError, match="Password hash cannot be empty"):
            FlextUser(
                id="test-id",
                username="user",
                email="user@example.com",
                password_hash="",
            ).validate_domain_rules()

    def test_user_domain_validation(self) -> None:
        """Test user domain validation via validate_domain_rules."""
        valid_user = FlextUser(
            id="test-id",
            username="validuser",
            email="valid@example.com",
            password_hash="valid-hash",
        )
        # Should not raise exception
        valid_user.validate_domain_rules()


class TestFlextSession:
    """Test FlextSession entity."""

    def test_session_creation(self) -> None:
        """Test session entity creation."""
        expires_at = datetime.now(UTC) + timedelta(hours=1)
        session = FlextSession(
            id="session-id",
            user_id="user-id",
            access_token="access-token",
            refresh_token="refresh-token",
            expires_at=expires_at,
            ip_address="192.168.1.1",
        )

        assert session.id == "session-id"
        assert session.user_id == "user-id"
        assert session.access_token == "access-token"
        assert session.refresh_token == "refresh-token"
        assert session.expires_at == expires_at
        assert session.ip_address == "192.168.1.1"

    def test_session_is_valid(self) -> None:
        """Test session is_valid method."""
        future_time = datetime.now(UTC) + timedelta(hours=1)
        valid_session = FlextSession(
            id="session-id",
            user_id="user-id",
            access_token="token",
            expires_at=future_time,
            status=FlextSessionStatus.ACTIVE,
        )
        assert valid_session.is_valid() is True

        expired_session = FlextSession(
            id="session-id",
            user_id="user-id",
            access_token="token",
            expires_at=datetime.now(UTC) - timedelta(hours=1),
            status=FlextSessionStatus.ACTIVE,
        )
        assert expired_session.is_valid() is False

        revoked_session = FlextSession(
            id="session-id",
            user_id="user-id",
            access_token="token",
            expires_at=future_time,
            status=FlextSessionStatus.REVOKED,
        )
        assert revoked_session.is_valid() is False

    def test_session_validate_domain_rules(self) -> None:
        """Test session domain rules validation."""
        future_time = datetime.now(UTC) + timedelta(hours=1)
        valid_session = FlextSession(
            id="session-id",
            user_id="user-id",
            access_token="token",
            expires_at=future_time,
        )
        # Should not raise
        valid_session.validate_domain_rules()

        # Test empty session ID
        with pytest.raises(ValueError, match="Session ID cannot be empty"):
            FlextSession(
                id="",
                user_id="user-id",
                access_token="token",
                expires_at=future_time,
            ).validate_domain_rules()

        # Test expired session
        past_time = datetime.now(UTC) - timedelta(hours=1)
        with pytest.raises(
            ValueError,
            match="Session expiration must be in the future",
        ):
            FlextSession(
                id="session-id",
                user_id="user-id",
                access_token="token",
                expires_at=past_time,
            ).validate_domain_rules()


class TestFlextPermission:
    """Test FlextPermission entity."""

    def test_permission_creation(self) -> None:
        """Test permission entity creation."""
        permission = FlextPermission(
            id="perm-id",
            name="read_users",
            description="Read users permission",
            resource="users",
            action="read",
        )

        assert permission.id == "perm-id"
        assert permission.name == "read_users"
        assert permission.description == "Read users permission"
        assert permission.resource == "users"
        assert permission.action == "read"

    def test_permission_is_valid(self) -> None:
        """Test permission is_valid method."""
        valid_permission = FlextPermission(
            id="perm-id",
            name="read_users",
            description="Read users",
            resource="users",
            action="read",
        )
        assert valid_permission.is_valid() is True

        invalid_permission = FlextPermission(
            id="perm-id",
            name="",  # Empty name
            description="Read users",
            resource="users",
            action="read",
        )
        assert invalid_permission.is_valid() is False

    def test_permission_validate_domain_rules(self) -> None:
        """Test permission domain rules validation."""
        valid_permission = FlextPermission(
            id="perm-id",
            name="read_users",
            description="Read users",
            resource="users",
            action="read",
        )
        # Should not raise
        valid_permission.validate_domain_rules()

        # Test empty name
        with pytest.raises(ValueError, match="Permission name cannot be empty"):
            FlextPermission(
                id="perm-id",
                name="",
                description="Read users",
                resource="users",
                action="read",
            ).validate_domain_rules()


class TestFlextRole:
    """Test FlextRole entity."""

    def test_role_creation(self) -> None:
        """Test role entity creation."""
        permission = FlextPermission(
            id="perm-id",
            name="read_users",
            description="Read users",
            resource="users",
            action="read",
        )

        role = FlextRole(
            id="role-id",
            name="user_manager",
            description="User management role",
            permissions=[permission],
        )

        assert role.id == "role-id"
        assert role.name == "user_manager"
        assert role.description == "User management role"
        assert len(role.permissions) == 1
        assert role.permissions[0] == permission

    def test_role_has_permission(self) -> None:
        """Test role has_permission method."""
        permission = FlextPermission(
            id="perm-id",
            name="read_users",
            description="Read users",
            resource="users",
            action="read",
        )

        role = FlextRole(
            id="role-id",
            name="user_manager",
            description="User management role",
            permissions=[permission],
        )

        assert role.has_permission("users", "read") is True
        assert role.has_permission("users", "write") is False
        assert role.has_permission("posts", "read") is False

    def test_role_validate_domain_rules(self) -> None:
        """Test role domain rules validation."""
        permission = FlextPermission(
            id="perm-id",
            name="read_users",
            description="Read users",
            resource="users",
            action="read",
        )

        valid_role = FlextRole(
            id="role-id",
            name="user_manager",
            description="User management role",
            permissions=[permission],
        )
        # Should not raise
        valid_role.validate_domain_rules()

        # Test empty name
        with pytest.raises(ValueError, match="Role name cannot be empty"):
            FlextRole(
                id="role-id",
                name="",
                description="User management role",
                permissions=[permission],
            ).validate_domain_rules()

        # Test invalid permission type
        with pytest.raises(
            TypeError,
            match="All permissions must be Permission instances",
        ):
            FlextRole(
                id="role-id",
                name="user_manager",
                description="User management role",
                permissions=["invalid"],  # type: ignore[list-item]
            ).validate_domain_rules()

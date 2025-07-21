"""Comprehensive tests for flext_auth.domain.entities module."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from uuid import UUID, uuid4

from flext_auth.domain.entities import (
    Permission,
    Role,
    Session,
    SessionRevokedEvent,
    User,
    UserAccountLockedEvent,
    UserCreatedEvent,
    UserEmailVerifiedEvent,
    UserLoggedInEvent,
    UserLoggedOutEvent,
    UserPasswordChangedEvent,
)


class TestUser:
    """Test User entity functionality."""

    def test_user_creation(self) -> None:
        """Test User entity can be created with defaults."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        assert isinstance(user.id, UUID)
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.password_hash == "hashed_password"
        assert user.role == "user"
        assert user.status == "active"
        assert user.email_verified is False
        assert user.email_verified_at is None
        assert user.last_login_at is None
        assert user.last_login_ip is None
        assert user.login_attempts == 0
        assert user.locked_until is None
        assert isinstance(user.created_at, datetime)
        assert isinstance(user.updated_at, datetime)

    def test_user_with_custom_values(self) -> None:
        """Test User entity with custom values."""
        user_id = uuid4()
        created_time = datetime.now(UTC)

        user = User(
            id=user_id,
            username="REDACTED_LDAP_BIND_PASSWORD",
            email="REDACTED_LDAP_BIND_PASSWORD@example.com",
            password_hash="REDACTED_LDAP_BIND_PASSWORD_hash",
            role="REDACTED_LDAP_BIND_PASSWORD",
            status="suspended",
            email_verified=True,
            created_at=created_time,
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        assert user.id == user_id
        assert user.role == "REDACTED_LDAP_BIND_PASSWORD"
        assert user.status == "suspended"
        assert user.email_verified is True
        assert user.created_at == created_time

    def test_is_active(self) -> None:
        """Test User is_active method."""
        active_user = User(
            username="active",
            email="active@example.com",
            password_hash="hash",
            status="active",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        inactive_user = User(
            username="inactive",
            email="inactive@example.com",
            password_hash="hash",
            status="suspended",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        assert active_user.is_active() is True
        assert inactive_user.is_active() is False

    def test_is_locked(self) -> None:
        """Test User is_locked method."""
        # User not locked
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )
        assert user.is_locked() is False

        # User locked in the future
        user.locked_until = datetime.now(UTC) + timedelta(minutes=30)
        assert user.is_locked() is True

        # User lock expired
        user.locked_until = datetime.now(UTC) - timedelta(minutes=30)
        assert user.is_locked() is False

    def test_is_email_verified(self) -> None:
        """Test User is_email_verified method."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        assert user.is_email_verified() is False

        user.email_verified = True
        assert user.is_email_verified() is True

    def test_verify_email(self) -> None:
        """Test User verify_email method."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        original_updated_at = user.updated_at

        user.verify_email()

        assert user.email_verified is True
        assert isinstance(user.email_verified_at, datetime)
        assert user.updated_at > original_updated_at

    def test_record_login_attempt_success(self) -> None:
        """Test User record_login_attempt with successful login."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            login_attempts=3,
            locked_until=datetime.now(UTC) + timedelta(minutes=10),
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
        )

        ip_address = "192.168.1.100"
        user.record_login_attempt(success=True, ip_address=ip_address)

        assert user.login_attempts == 0
        assert isinstance(user.last_login_at, datetime)
        assert user.last_login_ip == ip_address
        assert user.locked_until is None

    def test_record_login_attempt_failure(self) -> None:
        """Test User record_login_attempt with failed login."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        # Record 4 failed attempts (should not lock)
        for i in range(4):
            user.record_login_attempt(success=False, ip_address="192.168.1.100")
            assert user.login_attempts == i + 1
            assert user.locked_until is None

        # 5th attempt should lock the account
        user.record_login_attempt(success=False, ip_address="192.168.1.100")
        assert user.login_attempts == 5
        assert user.locked_until is not None
        assert user.locked_until > datetime.now(UTC)

    def test_unlock_account(self) -> None:
        """Test User unlock_account method."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            login_attempts=5,
            locked_until=datetime.now(UTC) + timedelta(minutes=30),
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
        )

        user.unlock_account()

        assert user.locked_until is None
        assert user.login_attempts == 0

    def test_change_password(self) -> None:
        """Test User change_password method."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="old_hash",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        original_updated_at = user.updated_at
        new_hash = "new_hash"

        user.change_password(new_hash)

        assert user.password_hash == new_hash
        assert user.updated_at > original_updated_at

    def test_suspend_account(self) -> None:
        """Test User suspend_account method."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            status="active",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        user.suspend_account()

        assert user.status == "suspended"
        assert not user.is_active()

    def test_activate_account(self) -> None:
        """Test User activate_account method."""
        user = User(
            username="test",
            email="test@example.com",
            password_hash="hash",
            status="suspended",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        user.activate_account()

        assert user.status == "active"
        assert user.is_active()


class TestRole:
    """Test Role entity functionality."""

    def test_role_creation(self) -> None:
        """Test Role entity can be created."""
        role = Role(name="REDACTED_LDAP_BIND_PASSWORD", description="")

        assert isinstance(role.id, UUID)
        assert role.name == "REDACTED_LDAP_BIND_PASSWORD"
        assert role.description == ""
        assert role.permissions == []
        assert role.is_system_role is False
        assert isinstance(role.created_at, datetime)
        assert isinstance(role.updated_at, datetime)

    def test_role_with_custom_values(self) -> None:
        """Test Role entity with custom values."""
        permissions = ["read:users", "write:users"]
        role = Role(
            name="moderator",
            description="Moderator role",
            permissions=permissions,
            is_system_role=True,
        )

        assert role.name == "moderator"
        assert role.description == "Moderator role"
        assert role.permissions == permissions
        assert role.is_system_role is True

    def test_add_permission(self) -> None:
        """Test Role add_permission method."""
        role = Role(name="test", description="")
        original_updated_at = role.updated_at

        permission = "read:posts"
        role.add_permission(permission)

        assert permission in role.permissions
        assert role.updated_at > original_updated_at

    def test_add_duplicate_permission(self) -> None:
        """Test Role add_permission with duplicate permission."""
        role = Role(name="test", description="", permissions=["read:posts"])
        original_permissions = role.permissions.copy()
        original_updated_at = role.updated_at

        role.add_permission("read:posts")

        # Should not add duplicate
        assert role.permissions == original_permissions
        assert role.updated_at == original_updated_at

    def test_remove_permission(self) -> None:
        """Test Role remove_permission method."""
        role = Role(
            name="test",
            description="",
            permissions=["read:posts", "write:posts"],
        )
        original_updated_at = role.updated_at

        role.remove_permission("read:posts")

        assert "read:posts" not in role.permissions
        assert "write:posts" in role.permissions
        assert role.updated_at > original_updated_at

    def test_remove_nonexistent_permission(self) -> None:
        """Test Role remove_permission with nonexistent permission."""
        role = Role(name="test", description="", permissions=["read:posts"])
        original_permissions = role.permissions.copy()
        original_updated_at = role.updated_at

        role.remove_permission("write:posts")

        # Should not change anything
        assert role.permissions == original_permissions
        assert role.updated_at == original_updated_at

    def test_has_permission(self) -> None:
        """Test Role has_permission method."""
        role = Role(
            name="test",
            description="",
            permissions=["read:posts", "write:posts"],
        )

        assert role.has_permission("read:posts") is True
        assert role.has_permission("write:posts") is True
        assert role.has_permission("delete:posts") is False


class TestSession:
    """Test Session entity functionality."""

    def test_session_creation(self) -> None:
        """Test Session entity can be created."""
        user_id = uuid4()
        token = "test_token"
        ip_address = "192.168.1.100"
        user_agent = "Test Agent"
        expires_at = datetime.now(UTC) + timedelta(hours=1)

        session = Session(
            user_id=user_id,
            token=token,
            refresh_token=None,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_at=expires_at,
        )

        assert isinstance(session.id, UUID)
        assert session.user_id == user_id
        assert session.token == token
        assert session.refresh_token is None
        assert session.ip_address == ip_address
        assert session.user_agent == user_agent
        assert session.status == "active"
        assert session.expires_at == expires_at
        assert isinstance(session.last_activity_at, datetime)
        assert isinstance(session.created_at, datetime)

    def test_session_create_new(self) -> None:
        """Test Session create_new class method."""
        user_id = uuid4()
        token = "test_token"
        ip_address = "192.168.1.100"
        user_agent = "Test Agent"
        refresh_token = "refresh_token"

        session = Session.create_new(
            user_id=user_id,
            token=token,
            ip_address=ip_address,
            user_agent=user_agent,
            expires_in_minutes=30,
            refresh_token=refresh_token,
        )

        assert session.user_id == user_id
        assert session.token == token
        assert session.refresh_token == refresh_token
        assert session.ip_address == ip_address
        assert session.user_agent == user_agent
        assert session.expires_at > datetime.now(UTC)
        assert session.expires_at <= datetime.now(UTC) + timedelta(minutes=31)

    def test_is_expired(self) -> None:
        """Test Session is_expired method."""
        user_id = uuid4()

        # Active session
        active_session = Session(
            user_id=user_id,
            token="token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )
        assert active_session.is_expired() is False

        # Expired session
        expired_session = Session(
            user_id=user_id,
            token="token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) - timedelta(minutes=30),
        )
        assert expired_session.is_expired() is True

    def test_is_active(self) -> None:
        """Test Session is_active method."""
        user_id = uuid4()

        # Active and not expired
        active_session = Session(
            user_id=user_id,
            token="token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            status="active",
        )
        assert active_session.is_active() is True

        # Revoked
        revoked_session = Session(
            user_id=user_id,
            token="token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
            status="revoked",
        )
        assert revoked_session.is_active() is False

        # Expired
        expired_session = Session(
            user_id=user_id,
            token="token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) - timedelta(minutes=30),
            status="active",
        )
        assert expired_session.is_active() is False

    def test_revoke(self) -> None:
        """Test Session revoke method."""
        session = Session(
            user_id=uuid4(),
            token="token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )

        session.revoke()

        assert session.status == "revoked"
        assert not session.is_active()

    def test_refresh(self) -> None:
        """Test Session refresh method."""
        session = Session(
            user_id=uuid4(),
            token="old_token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )

        original_last_activity = session.last_activity_at
        new_token = "new_token"

        session.refresh(new_token, expires_in_minutes=60)

        assert session.token == new_token
        assert session.expires_at > datetime.now(UTC) + timedelta(minutes=50)
        assert session.last_activity_at > original_last_activity

    def test_update_activity(self) -> None:
        """Test Session update_activity method."""
        session = Session(
            user_id=uuid4(),
            token="token",
            refresh_token=None,
            ip_address="192.168.1.100",
            user_agent="Agent",
            expires_at=datetime.now(UTC) + timedelta(minutes=30),
        )

        original_last_activity = session.last_activity_at

        session.update_activity()

        assert session.last_activity_at > original_last_activity


class TestPermission:
    """Test Permission entity functionality."""

    def test_permission_creation(self) -> None:
        """Test Permission entity can be created."""
        permission = Permission(
            name="read_users",
            description="",
            resource="users",
            action="read",
        )

        assert isinstance(permission.id, UUID)
        assert permission.name == "read_users"
        assert permission.description == ""
        assert permission.resource == "users"
        assert permission.action == "read"
        assert isinstance(permission.created_at, datetime)

    def test_permission_with_description(self) -> None:
        """Test Permission entity with description."""
        permission = Permission(
            name="write_posts",
            description="Allow writing posts",
            resource="posts",
            action="write",
        )

        assert permission.description == "Allow writing posts"

    def test_permission_full_name(self) -> None:
        """Test Permission full_name property."""
        permission = Permission(
            name="delete_comments",
            description="",
            resource="comments",
            action="delete",
        )

        assert permission.full_name == "comments:delete"


class TestDomainEvents:
    """Test domain events."""

    def test_user_created_event(self) -> None:
        """Test UserCreatedEvent creation."""
        user_id = uuid4()
        event = UserCreatedEvent(
            user_id=user_id,
            username="testuser",
            email="test@example.com",
        )

        assert event.user_id == user_id
        assert event.username == "testuser"
        assert event.email == "test@example.com"
        # DomainEvent should have occurred_at from flext_core
        assert hasattr(event, "occurred_at") or hasattr(event, "timestamp")

    def test_user_email_verified_event(self) -> None:
        """Test UserEmailVerifiedEvent creation."""
        user_id = uuid4()
        verified_at = datetime.now(UTC)

        event = UserEmailVerifiedEvent(
            user_id=user_id,
            email="test@example.com",
            verified_at=verified_at,
        )

        assert event.user_id == user_id
        assert event.email == "test@example.com"
        assert event.verified_at == verified_at

    def test_user_logged_in_event(self) -> None:
        """Test UserLoggedInEvent creation."""
        user_id = uuid4()
        session_id = uuid4()
        login_at = datetime.now(UTC)

        event = UserLoggedInEvent(
            user_id=user_id,
            session_id=session_id,
            ip_address="192.168.1.100",
            user_agent="Test Agent",
            login_at=login_at,
        )

        assert event.user_id == user_id
        assert event.session_id == session_id
        assert event.ip_address == "192.168.1.100"
        assert event.user_agent == "Test Agent"
        assert event.login_at == login_at

    def test_user_logged_out_event(self) -> None:
        """Test UserLoggedOutEvent creation."""
        user_id = uuid4()
        session_id = uuid4()
        logout_at = datetime.now(UTC)

        event = UserLoggedOutEvent(
            user_id=user_id,
            session_id=session_id,
            logout_at=logout_at,
        )

        assert event.user_id == user_id
        assert event.session_id == session_id
        assert event.logout_at == logout_at

    def test_user_password_changed_event(self) -> None:
        """Test UserPasswordChangedEvent creation."""
        user_id = uuid4()
        changed_at = datetime.now(UTC)

        event = UserPasswordChangedEvent(
            user_id=user_id,
            changed_at=changed_at,
        )

        assert event.user_id == user_id
        assert event.changed_at == changed_at

    def test_user_account_locked_event(self) -> None:
        """Test UserAccountLockedEvent creation."""
        user_id = uuid4()
        locked_until = datetime.now(UTC) + timedelta(minutes=30)

        event = UserAccountLockedEvent(
            user_id=user_id,
            locked_until=locked_until,
            reason="Too many failed login attempts",
        )

        assert event.user_id == user_id
        assert event.locked_until == locked_until
        assert event.reason == "Too many failed login attempts"

    def test_session_revoked_event(self) -> None:
        """Test SessionRevokedEvent creation."""
        session_id = uuid4()
        user_id = uuid4()
        revoked_at = datetime.now(UTC)

        event = SessionRevokedEvent(
            session_id=session_id,
            user_id=user_id,
            revoked_at=revoked_at,
            reason="user_logout",
        )

        assert event.session_id == session_id
        assert event.user_id == user_id
        assert event.revoked_at == revoked_at
        assert event.reason == "user_logout"

    def test_session_revoked_event_default_reason(self) -> None:
        """Test SessionRevokedEvent with default reason."""
        event = SessionRevokedEvent(
            session_id=uuid4(),
            user_id=uuid4(),
            revoked_at=datetime.now(UTC),
        )

        assert event.reason == "manual_revocation"


class TestEntityIntegration:
    """Test integration between entities."""

    def test_user_session_workflow(self) -> None:
        """Test typical user session workflow."""
        # Create user
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        # Verify email
        user.verify_email()
        assert user.is_email_verified()

        # Create session
        session = Session.create_new(
            user_id=user.id,
            token="session_token",
            ip_address="192.168.1.100",
            user_agent="Test Browser",
        )

        # Record successful login
        user.record_login_attempt(success=True, ip_address="192.168.1.100")

        # Verify states
        assert session.is_active()
        assert user.last_login_ip == "192.168.1.100"
        assert user.login_attempts == 0

        # End session
        session.revoke()
        assert not session.is_active()

    def test_user_lockout_workflow(self) -> None:
        """Test user account lockout workflow."""
        user = User(
            username="testuser",
            email="test@example.com",
            password_hash="hashed_password",
            email_verified_at=None,
            last_login_at=None,
            last_login_ip=None,
            locked_until=None,
        )

        # Simulate 5 failed login attempts
        for _ in range(5):
            user.record_login_attempt(success=False, ip_address="192.168.1.100")

        # User should be locked
        assert user.is_locked()
        assert user.login_attempts == 5

        # Unlock user
        user.unlock_account()
        assert not user.is_locked()
        assert user.login_attempts == 0

    def test_role_permission_workflow(self) -> None:
        """Test role and permission workflow."""
        # Create role
        role = Role(name="content_manager", description="")

        # Add permissions
        permissions = ["read:posts", "write:posts", "edit:posts"]
        for permission in permissions:
            role.add_permission(permission)

        # Verify permissions
        for permission in permissions:
            assert role.has_permission(permission)

        assert not role.has_permission("delete:posts")

        # Remove permission
        role.remove_permission("edit:posts")
        assert not role.has_permission("edit:posts")
        assert role.has_permission("read:posts")

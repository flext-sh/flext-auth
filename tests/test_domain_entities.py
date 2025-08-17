"""Test domain entities following flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from flext_auth import (
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

      if user.id != "test-user-id":
          raise AssertionError(f"Expected {'test-user-id'}, got {user.id}")
      assert user.username == "testuser"
      if user.email != "test@example.com":
          raise AssertionError(f"Expected {'test@example.com'}, got {user.email}")
      assert user.role == FlextUserRole.USER
      if user.status != FlextUserStatus.ACTIVE:
          raise AssertionError(
              f"Expected {FlextUserStatus.ACTIVE}, got {user.status}",
          )

    def test_user_is_active(self) -> None:
      """Test user is_active method."""
      user = FlextUser(
          id="test-id",
          username="test",
          email="test@example.com",
          password_hash="hash",
          status=FlextUserStatus.ACTIVE,
      )
      if not (user.is_active()):
          raise AssertionError(f"Expected True, got {user.is_active()}")

      user_inactive = FlextUser(
          id="test-id",
          username="test",
          email="test@example.com",
          password_hash="hash",
          status=FlextUserStatus.INACTIVE,
      )
      if user_inactive.is_active():
          raise AssertionError(f"Expected False, got {user_inactive.is_active()}")

    def test_user_is_locked(self) -> None:
      """Test user is_locked method."""
      user_locked = FlextUser(
          id="test-id",
          username="test",
          email="test@example.com",
          password_hash="hash",
          status=FlextUserStatus.LOCKED,
      )
      if not (user_locked.is_locked()):
          raise AssertionError(f"Expected True, got {user_locked.is_locked()}")

      future_time = datetime.now(UTC) + timedelta(hours=1)
      user_temp_locked = FlextUser(
          id="test-id",
          username="test",
          email="test@example.com",
          password_hash="hash",
          locked_until=future_time,
      )
      if not (user_temp_locked.is_locked()):
          raise AssertionError(f"Expected True, got {user_temp_locked.is_locked()}")

    def test_user_is_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
      """Test user is_REDACTED_LDAP_BIND_PASSWORD method."""
      REDACTED_LDAP_BIND_PASSWORD_user = FlextUser(
          id="test-id",
          username="REDACTED_LDAP_BIND_PASSWORD",
          email="REDACTED_LDAP_BIND_PASSWORD@example.com",
          password_hash="hash",
          role=FlextUserRole.ADMIN,
      )
      if not (REDACTED_LDAP_BIND_PASSWORD_user.is_REDACTED_LDAP_BIND_PASSWORD()):
          raise AssertionError(f"Expected True, got {REDACTED_LDAP_BIND_PASSWORD_user.is_REDACTED_LDAP_BIND_PASSWORD()}")

      regular_user = FlextUser(
          id="test-id",
          username="user",
          email="user@example.com",
          password_hash="hash",
          role=FlextUserRole.USER,
      )
      if regular_user.is_REDACTED_LDAP_BIND_PASSWORD():
          raise AssertionError(f"Expected False, got {regular_user.is_REDACTED_LDAP_BIND_PASSWORD()}")

    def test_user_validate_business_rules(self) -> None:
      """Test user domain rules validation."""
      valid_user = FlextUser(
          id="test-id",
          username="validuser",
          email="valid@example.com",
          password_hash="valid-hash",
      )
      # Should not raise
      valid_user.validate_business_rules()

      # Test short username
      with pytest.raises(ValueError, match="Username must be at least 3 characters"):
          FlextUser(
              id="test-id",
              username="ab",
              email="test@example.com",
              password_hash="hash",
          ).validate_business_rules()

      # Test long username
      with pytest.raises(ValueError, match="Username must be at most 50 characters"):
          FlextUser(
              id="test-id",
              username="a" * 51,
              email="test@example.com",
              password_hash="hash",
          ).validate_business_rules()

      # Test invalid email
      with pytest.raises(ValueError, match="Email must contain @ symbol"):
          FlextUser(
              id="test-id",
              username="user",
              email="invalid-email",
              password_hash="hash",
          ).validate_business_rules()

      # Test empty password hash
      with pytest.raises(ValueError, match="Password hash cannot be empty"):
          FlextUser(
              id="test-id",
              username="user",
              email="user@example.com",
              password_hash="",
          ).validate_business_rules()

    def test_user_domain_validation(self) -> None:
      """Test user domain validation via validate_business_rules."""
      valid_user = FlextUser(
          id="test-id",
          username="validuser",
          email="valid@example.com",
          password_hash="valid-hash",
      )
      # Should not raise exception
      valid_user.validate_business_rules()


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

      if session.id != "session-id":
          raise AssertionError(f"Expected {'session-id'}, got {session.id}")
      assert session.user_id == "user-id"
      if session.access_token != "access-token":
          raise AssertionError(
              f"Expected {'access-token'}, got {session.access_token}",
          )
      assert session.refresh_token == "refresh-token"
      if session.expires_at != expires_at:
          raise AssertionError(f"Expected {expires_at}, got {session.expires_at}")
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
      if not (valid_session.is_valid()):
          raise AssertionError(f"Expected True, got {valid_session.is_valid()}")

      expired_session = FlextSession(
          id="session-id",
          user_id="user-id",
          access_token="token",
          expires_at=datetime.now(UTC) - timedelta(hours=1),
          status=FlextSessionStatus.ACTIVE,
      )
      if expired_session.is_valid():
          raise AssertionError(f"Expected False, got {expired_session.is_valid()}")

      revoked_session = FlextSession(
          id="session-id",
          user_id="user-id",
          access_token="token",
          expires_at=future_time,
          status=FlextSessionStatus.REVOKED,
      )
      if revoked_session.is_valid():
          raise AssertionError(f"Expected False, got {revoked_session.is_valid()}")

    def test_session_validate_business_rules(self) -> None:
      """Test session domain rules validation."""
      future_time = datetime.now(UTC) + timedelta(hours=1)
      valid_session = FlextSession(
          id="session-id",
          user_id="user-id",
          access_token="token",
          expires_at=future_time,
      )
      # Should not raise
      valid_session.validate_business_rules()

      # Test empty user ID (base class handles empty session ID)
      with pytest.raises(ValueError, match="User ID cannot be empty"):
          FlextSession(
              id="session-id",
              user_id="",
              access_token="token",
              expires_at=future_time,
          ).validate_business_rules()

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
          ).validate_business_rules()


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

      if permission.id != "perm-id":
          raise AssertionError(f"Expected {'perm-id'}, got {permission.id}")
      assert permission.name == "read_users"
      if permission.description != "Read users permission":
          raise AssertionError(
              f"Expected {'Read users permission'}, got {permission.description}",
          )
      assert permission.resource == "users"
      if permission.action != "read":
          raise AssertionError(f"Expected {'read'}, got {permission.action}")

    def test_permission_is_valid(self) -> None:
      """Test permission is_valid method."""
      valid_permission = FlextPermission(
          id="perm-id",
          name="read_users",
          description="Read users",
          resource="users",
          action="read",
      )
      if not (valid_permission.is_valid()):
          raise AssertionError(f"Expected True, got {valid_permission.is_valid()}")

      invalid_permission = FlextPermission(
          id="perm-id",
          name="",  # Empty name
          description="Read users",
          resource="users",
          action="read",
      )
      if invalid_permission.is_valid():
          raise AssertionError(f"Expected False, got {invalid_permission.is_valid()}")

    def test_permission_validate_business_rules(self) -> None:
      """Test permission domain rules validation."""
      valid_permission = FlextPermission(
          id="perm-id",
          name="read_users",
          description="Read users",
          resource="users",
          action="read",
      )
      # Should not raise
      valid_permission.validate_business_rules()

      # Test empty name
      with pytest.raises(ValueError, match="Permission name cannot be empty"):
          FlextPermission(
              id="perm-id",
              name="",
              description="Read users",
              resource="users",
              action="read",
          ).validate_business_rules()


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

      if role.id != "role-id":
          raise AssertionError(f"Expected {'role-id'}, got {role.id}")
      assert role.name == "user_manager"
      if role.description != "User management role":
          raise AssertionError(
              f"Expected {'User management role'}, got {role.description}",
          )
      assert len(role.permissions) == 1
      if role.permissions[0] != permission:
          raise AssertionError(f"Expected {permission}, got {role.permissions[0]}")

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

      if not (role.has_permission("users", "read")):
          raise AssertionError(
              f"Expected True, got {role.has_permission('users', 'read')}",
          )
      if role.has_permission("users", "write"):
          raise AssertionError(
              f"Expected False, got {role.has_permission('users', 'write')}",
          )
      assert role.has_permission("posts", "read") is False

    def test_role_validate_business_rules(self) -> None:
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
      valid_role.validate_business_rules()

      # Test empty name - returns FlextResult failure instead of raising
      invalid_role = FlextRole(
          id="role-id",
          name="",
          description="User management role",
          permissions=[permission],
      )
      result = invalid_role.validate_business_rules()
      assert not result.success
      assert "Role name cannot be empty" in result.error

      # Test invalid permission type - Pydantic raises ValidationError
      with pytest.raises(
          ValueError,  # Pydantic ValidationError inherits from ValueError
          match="Input should be a valid dictionary or instance of FlextPermission",
      ):
          FlextRole(
              id="role-id",
              name="user_manager",
              description="User management role",
              permissions=["invalid"],
          ).validate_business_rules()

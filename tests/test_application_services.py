"""Test application services following flext-core patterns.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from flext_auth import (
    FlextAuthenticationService,
    FlextAuthorizationService,
    FlextPermission,
    FlextRole,
    FlextSession,
    FlextSessionService,
    FlextSessionStatus,
    FlextUser,
    FlextUserRole,
    FlextUserStatus,
)


class TestFlextAuthenticationService:
    """Test FlextAuthenticationService."""

    def test_authentication_service_creation(self) -> None:
        """Test authentication service creation."""
        service = FlextAuthenticationService()
        assert service is not None

    def test_create_user_success(self) -> None:
        """Test successful user creation."""
        service = FlextAuthenticationService()
        result = service.create_user("testuser", "test@example.com", "TestPass123!")

        assert result.success
        user = result.data
        if user.username != "testuser":
            raise AssertionError(f"Expected {'testuser'}, got {user.username}")
        assert str(user.email) == "test@example.com"
        if user.role != FlextUserRole.USER:
            raise AssertionError(f"Expected {FlextUserRole.USER}, got {user.role}")
        assert user.status == FlextUserStatus.ACTIVE

    def test_create_user_invalid_username(self) -> None:
        """Test user creation with invalid username."""
        service = FlextAuthenticationService()
        result = service.create_user("ab", "test@example.com", "TestPass123!")

        assert not result.success
        if "Username must be at least 3 characters" not in result.error:
            raise AssertionError(
                f"Expected {'Username must be at least 3 characters'} in {result.error}",
            )

    def test_create_user_invalid_email(self) -> None:
        """Test user creation with invalid email."""
        service = FlextAuthenticationService()
        result = service.create_user("testuser", "invalid-email", "TestPass123!")

        assert not result.success
        if "Input should be a valid email address" not in result.error:
            raise AssertionError(
                f"Expected {'Input should be a valid email address'} in {result.error}",
            )

    def test_create_user_invalid_password(self) -> None:
        """Test user creation with invalid password."""
        service = FlextAuthenticationService()
        result = service.create_user("testuser", "test@example.com", "weak")

        assert not result.success
        if "Password must be at least 8 characters" not in result.error:
            raise AssertionError(
                f"Expected {'Password must be at least 8 characters'} in {result.error}",
            )

    def test_authenticate_user_success(self) -> None:
        """Test successful user authentication."""
        service = FlextAuthenticationService()

        # Create user first
        create_result = service.create_user(
            "testuser",
            "test@example.com",
            "TestPass123!",
        )
        assert create_result.success
        user = create_result.data

        # Prepare users dict for authentication
        users = {user.username: user}

        # Authenticate
        auth_result = service.authenticate_user("testuser", "TestPass123!", users)
        assert auth_result.success
        authenticated_user = auth_result.data
        if authenticated_user.username != "testuser":
            raise AssertionError(
                f"Expected {'testuser'}, got {authenticated_user.username}",
            )

    def test_authenticate_user_wrong_password(self) -> None:
        """Test authentication with wrong password."""
        service = FlextAuthenticationService()

        # Create user first
        create_result = service.create_user(
            "testuser",
            "test@example.com",
            "TestPass123!",
        )
        assert create_result.success
        user = create_result.data

        # Prepare users dict for authentication
        users = {user.username: user}

        # Authenticate with wrong password
        auth_result = service.authenticate_user("testuser", "WrongPass123!", users)
        assert not auth_result.success
        if "Invalid credentials" not in auth_result.error:
            raise AssertionError(
                f"Expected {'Invalid credentials'} in {auth_result.error}",
            )

    def test_authenticate_user_not_found(self) -> None:
        """Test authentication with non-existent user."""
        service = FlextAuthenticationService()

        # Empty users dict
        users: dict[str, FlextUser] = {}

        # Authenticate non-existent user
        auth_result = service.authenticate_user("nonexistent", "TestPass123!", users)
        assert not auth_result.success
        if "User not found" not in auth_result.error:
            raise AssertionError(f"Expected {'User not found'} in {auth_result.error}")

    def test_change_password_success(self) -> None:
        """Test successful password change."""
        service = FlextAuthenticationService()

        # Create user first
        create_result = service.create_user(
            "testuser",
            "test@example.com",
            "OldPass123!",
        )
        assert create_result.success
        user = create_result.data

        # Change password
        change_result = service.change_password(user, "OldPass123!", "NewPass123!")
        assert change_result.success
        if not (change_result.data):
            raise AssertionError(f"Expected True, got {change_result.data}")

    def test_change_password_wrong_old_password(self) -> None:
        """Test password change with wrong old password."""
        service = FlextAuthenticationService()

        # Create user first
        create_result = service.create_user(
            "testuser",
            "test@example.com",
            "OldPass123!",
        )
        assert create_result.success
        user = create_result.data

        # Change password with wrong old password
        change_result = service.change_password(user, "WrongOldPass!", "NewPass123!")
        assert not change_result.success
        if "Current password is incorrect" not in change_result.error:
            raise AssertionError(
                f"Expected {'Current password is incorrect'} in {change_result.error}",
            )

    def test_change_password_invalid_new_password(self) -> None:
        """Test password change with invalid new password."""
        service = FlextAuthenticationService()

        # Create user first
        create_result = service.create_user(
            "testuser",
            "test@example.com",
            "OldPass123!",
        )
        assert create_result.success
        user = create_result.data

        # Change password with invalid new password
        change_result = service.change_password(user, "OldPass123!", "weak")
        assert not change_result.success
        if "Password must be at least 8 characters" not in change_result.error:
            raise AssertionError(
                f"Expected {'Password must be at least 8 characters'} in {change_result.error}",
            )


class TestFlextSessionService:
    """Test FlextSessionService."""

    def test_session_service_creation(self) -> None:
        """Test session service creation."""
        service = FlextSessionService()
        assert service is not None

    def test_create_session_success(self) -> None:
        """Test successful session creation."""
        service = FlextSessionService()

        # Create user for session
        user = FlextUser(
            id="user-123",
            username="testuser",
            email="test@example.com",
            password_hash="hashed-password",
        )

        # Create session
        result = service.create_session(
            user,
            expires_minutes=60,
            ip_address="192.168.1.1",
            user_agent="Test Browser",
        )

        assert result.success
        session = result.data
        if session.user_id != user.id:
            raise AssertionError(f"Expected {user.id}, got {session.user_id}")
        assert session.ip_address == "192.168.1.1"
        if session.user_agent != "Test Browser":
            raise AssertionError(f"Expected {'Test Browser'}, got {session.user_agent}")
        assert session.status == FlextSessionStatus.ACTIVE

    def test_create_session_with_defaults(self) -> None:
        """Test session creation with default values."""
        service = FlextSessionService()

        # Create user for session
        user = FlextUser(
            id="user-123",
            username="testuser",
            email="test@example.com",
            password_hash="hashed-password",
        )

        # Create session with defaults
        result = service.create_session(user)

        assert result.success
        session = result.data
        if session.user_id != user.id:
            raise AssertionError(f"Expected {user.id}, got {session.user_id}")
        assert session.ip_address is None
        assert session.user_agent is None
        if session.status != FlextSessionStatus.ACTIVE:
            raise AssertionError(
                f"Expected {FlextSessionStatus.ACTIVE}, got {session.status}",
            )

    def test_validate_session_success(self) -> None:
        """Test successful session validation."""
        service = FlextSessionService()

        # Create valid session
        session = FlextSession(
            id="session-123",
            user_id="user-123",
            access_token="valid-token",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            status=FlextSessionStatus.ACTIVE,
        )

        # Validate session
        result = service.validate_session(session)
        assert result.success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

    def test_validate_session_expired(self) -> None:
        """Test validation of expired session."""
        service = FlextSessionService()

        # Create expired session
        session = FlextSession(
            id="session-123",
            user_id="user-123",
            access_token="valid-token",
            expires_at=datetime.now(UTC) - timedelta(hours=1),
            status=FlextSessionStatus.ACTIVE,
        )

        # Validate session
        result = service.validate_session(session)
        assert result.success
        if result.data:
            raise AssertionError(f"Expected False, got {result.data}")

    def test_validate_session_revoked(self) -> None:
        """Test validation of revoked session."""
        service = FlextSessionService()

        # Create revoked session
        session = FlextSession(
            id="session-123",
            user_id="user-123",
            access_token="valid-token",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            status=FlextSessionStatus.REVOKED,
        )

        # Validate session
        result = service.validate_session(session)
        assert result.success
        if result.data:
            raise AssertionError(f"Expected False, got {result.data}")


class TestFlextAuthorizationService:
    """Test FlextAuthorizationService."""

    def test_authorization_service_creation(self) -> None:
        """Test authorization service creation."""
        service = FlextAuthorizationService()
        assert service is not None

    def test_create_role_success(self) -> None:
        """Test successful role creation."""
        service = FlextAuthorizationService()

        # Create permission first
        permission = FlextPermission(
            id="perm-123",
            name="read_users",
            description="Read users",
            resource="users",
            action="read",
        )

        # Create role
        result = service.create_role(
            "user_manager",
            "User management role",
            [permission],
        )

        assert result.success
        role = result.data
        if role.name != "user_manager":
            raise AssertionError(f"Expected {'user_manager'}, got {role.name}")
        assert role.description == "User management role"
        if len(role.permissions) != 1:
            raise AssertionError(f"Expected {1}, got {len(role.permissions)}")
        assert role.permissions[0] == permission

    def test_create_role_with_no_permissions(self) -> None:
        """Test role creation with no permissions."""
        service = FlextAuthorizationService()

        # Create role without permissions
        result = service.create_role("basic_role", "Basic role")

        assert result.success
        role = result.data
        if role.name != "basic_role":
            raise AssertionError(f"Expected {'basic_role'}, got {role.name}")
        assert role.description == "Basic role"
        if len(role.permissions) != 0:
            raise AssertionError(f"Expected {0}, got {len(role.permissions)}")

    def test_create_role_invalid_name(self) -> None:
        """Test role creation with invalid name."""
        service = FlextAuthorizationService()

        # Create role with empty name
        result = service.create_role("", "Role description")

        assert not result.success
        if "Role name cannot be empty" not in result.error:
            raise AssertionError(
                f"Expected {'Role name cannot be empty'} in {result.error}",
            )

    def test_check_permission_success(self) -> None:
        """Test successful permission check."""
        service = FlextAuthorizationService()

        # Create permission
        permission = FlextPermission(
            id="perm-123",
            name="read_users",
            description="Read users",
            resource="users",
            action="read",
        )

        # Create role with permission
        role = FlextRole(
            id="role-123",
            name="user_manager",
            description="User management role",
            permissions=[permission],
        )

        # Create user
        user = FlextUser(
            id="user-123",
            username="testuser",
            email="test@example.com",
            password_hash="hashed-password",
        )

        # Prepare roles dict
        roles = {"user_manager": role}

        # Check permission
        result = service.check_permission(user, "users", "read", roles)
        assert result.success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

    def test_check_permission_no_roles(self) -> None:
        """Test permission check with no roles."""
        service = FlextAuthorizationService()

        # Create user
        user = FlextUser(
            id="user-123",
            username="testuser",
            email="test@example.com",
            password_hash="hashed-password",
        )

        # Check permission without roles
        result = service.check_permission(user, "users", "read")
        assert result.success
        if result.data:
            raise AssertionError(f"Expected False, got {result.data}")

    def test_check_permission_REDACTED_LDAP_BIND_PASSWORD_user(self) -> None:
        """Test permission check for REDACTED_LDAP_BIND_PASSWORD user."""
        service = FlextAuthorizationService()

        # Create REDACTED_LDAP_BIND_PASSWORD user
        user = FlextUser(
            id="user-123",
            username="REDACTED_LDAP_BIND_PASSWORD",
            email="REDACTED_LDAP_BIND_PASSWORD@example.com",
            password_hash="hashed-password",
            role=FlextUserRole.ADMIN,
        )

        # Check permission for REDACTED_LDAP_BIND_PASSWORD (should have all permissions)
        result = service.check_permission(user, "users", "delete")
        assert result.success
        if not (result.data):
            raise AssertionError(f"Expected True, got {result.data}")

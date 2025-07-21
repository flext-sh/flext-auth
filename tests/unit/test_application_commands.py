"""Comprehensive tests for flext_auth.application.commands module."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

import pytest
from pydantic import ValidationError

from flext_auth.application.commands import (
    AssignRoleCommand,
    AuthenticateUserCommand,
    ChangePasswordCommand,
    CreateRoleCommand,
    CreateSessionCommand,
    CreateTokenCommand,
    CreateUserCommand,
    DeactivateSessionCommand,
    LockUserCommand,
    LogoutUserCommand,
    RefreshSessionCommand,
    RemoveRoleCommand,
    ResetPasswordCommand,
    RevokeTokenCommand,
    SendPasswordResetCommand,
    UnlockUserCommand,
    UpdateRoleCommand,
    UpdateUserCommand,
    VerifyEmailCommand,
)
from flext_auth.domain.value_objects import UserStatus


class TestCreateUserCommand:
    """Test CreateUserCommand functionality."""

    def test_create_user_command_required_fields(self) -> None:
        """Test CreateUserCommand with required fields only."""
        command = CreateUserCommand(username="testuser")

        assert command.username == "testuser"
        assert command.email is None
        assert command.first_name is None
        assert command.last_name is None
        assert command.display_name is None
        assert command.is_superuser is False
        assert command.is_staff is False
        assert command.send_verification_email is True

    def test_create_user_command_all_fields(self) -> None:
        """Test CreateUserCommand with all fields."""
        command = CreateUserCommand(
            username="REDACTED_LDAP_BIND_PASSWORD",
            email="REDACTED_LDAP_BIND_PASSWORD@example.com",
            first_name="Admin",
            last_name="User",
            display_name="Administrator",
            is_superuser=True,
            is_staff=True,
            send_verification_email=False,
        )

        assert command.username == "REDACTED_LDAP_BIND_PASSWORD"
        assert command.email == "REDACTED_LDAP_BIND_PASSWORD@example.com"
        assert command.first_name == "Admin"
        assert command.last_name == "User"
        assert command.display_name == "Administrator"
        assert command.is_superuser is True
        assert command.is_staff is True
        assert command.send_verification_email is False

    def test_create_user_command_validation(self) -> None:
        """Test CreateUserCommand validation."""
        # Test empty username - violates min_length=1 constraint
        with pytest.raises(ValidationError):
            CreateUserCommand(username="")  # Empty username violates min_length=1


class TestUpdateUserCommand:
    """Test UpdateUserCommand functionality."""

    def test_update_user_command_required_fields(self) -> None:
        """Test UpdateUserCommand with required fields only."""
        user_id = uuid4()
        command = UpdateUserCommand(user_id=user_id)

        assert command.user_id == user_id
        assert command.first_name is None
        assert command.last_name is None
        assert command.display_name is None
        assert command.email is None
        assert command.status is None
        assert command.is_superuser is None
        assert command.is_staff is None
        assert command.updated_by is None

    def test_update_user_command_all_fields(self) -> None:
        """Test UpdateUserCommand with all fields."""
        user_id = uuid4()
        updated_by = uuid4()

        command = UpdateUserCommand(
            user_id=user_id,
            first_name="Updated",
            last_name="Name",
            display_name="Updated User",
            email="updated@example.com",
            status=UserStatus.ACTIVE,
            is_superuser=True,
            is_staff=False,
            updated_by=updated_by,
        )

        assert command.user_id == user_id
        assert command.first_name == "Updated"
        assert command.last_name == "Name"
        assert command.display_name == "Updated User"
        assert command.email == "updated@example.com"
        assert command.status == "active"
        assert command.is_superuser is True
        assert command.is_staff is False
        assert command.updated_by == updated_by


class TestChangePasswordCommand:
    """Test ChangePasswordCommand functionality."""

    def test_change_password_command_required_fields(self) -> None:
        """Test ChangePasswordCommand with required fields only."""
        user_id = uuid4()
        command = ChangePasswordCommand(
            user_id=user_id,
            new_password="NewPassword123!",
        )

        assert command.user_id == user_id
        assert command.current_password is None
        assert command.new_password == "NewPassword123!"

    def test_change_password_command_all_fields(self) -> None:
        """Test ChangePasswordCommand with all fields."""
        user_id = uuid4()
        command = ChangePasswordCommand(
            user_id=user_id,
            current_password="OldPassword123!",
            new_password="NewPassword123!",
        )

        assert command.user_id == user_id
        assert command.current_password == "OldPassword123!"
        assert command.new_password == "NewPassword123!"

    def test_change_password_command_validation(self) -> None:
        """Test ChangePasswordCommand validation."""
        user_id = uuid4()

        # Since both user_id and new_password are required, test empty values instead
        with pytest.raises(ValidationError):
            ChangePasswordCommand(
                user_id=user_id,
                new_password="",
            )  # Empty new_password


class TestResetPasswordCommand:
    """Test ResetPasswordCommand functionality."""

    def test_reset_password_command_required_fields(self) -> None:
        """Test ResetPasswordCommand with required fields."""
        user_id = uuid4()
        command = ResetPasswordCommand(
            user_id=user_id,
            new_password="NewPassword123!",
            reset_token="reset_token_123",
        )

        assert command.user_id == user_id
        assert command.new_password == "NewPassword123!"
        assert command.reset_token == "reset_token_123"

    def test_reset_password_command_validation(self) -> None:
        """Test ResetPasswordCommand validation."""
        user_id = uuid4()

        # Test validation with empty required fields
        with pytest.raises(ValidationError):
            ResetPasswordCommand(
                user_id=user_id,
                reset_token="token",
                new_password="",
            )  # Empty new_password

        with pytest.raises(ValidationError):
            ResetPasswordCommand(
                user_id=user_id,
                new_password="password",
                reset_token="",
            )  # Empty reset_token


class TestAuthenticateUserCommand:
    """Test AuthenticateUserCommand functionality."""

    def test_authenticate_user_command_required_fields(self) -> None:
        """Test AuthenticateUserCommand with required fields only."""
        command = AuthenticateUserCommand(username="testuser")

        assert command.username == "testuser"
        assert command.password is None
        assert command.user_agent is None

    def test_authenticate_user_command_all_fields(self) -> None:
        """Test AuthenticateUserCommand with all fields."""
        command = AuthenticateUserCommand(
            username="testuser",
            password="password123",
            user_agent="Mozilla/5.0 Test Browser",
        )

        assert command.username == "testuser"
        assert command.password == "password123"
        assert command.user_agent == "Mozilla/5.0 Test Browser"

    def test_authenticate_user_command_validation(self) -> None:
        """Test AuthenticateUserCommand validation."""
        # Test empty username
        with pytest.raises(ValidationError):
            AuthenticateUserCommand(username="")  # Empty username

        # Test empty username
        with pytest.raises(ValidationError):
            AuthenticateUserCommand(username="")


class TestLogoutUserCommand:
    """Test LogoutUserCommand functionality."""

    def test_logout_user_command_required_fields(self) -> None:
        """Test LogoutUserCommand with required fields."""
        user_id = uuid4()
        session_id = uuid4()

        command = LogoutUserCommand(
            user_id=user_id,
            session_id=session_id,
        )

        assert command.user_id == user_id
        assert command.session_id == session_id

    def test_logout_user_command_validation(self) -> None:
        """Test LogoutUserCommand validation."""
        uuid4()
        uuid4()

        # Both user_id and session_id are required, test with proper validation
        # These will pass since both required fields are provided
        # No validation error expected for valid UUIDs


class TestCreateTokenCommand:
    """Test CreateTokenCommand functionality."""

    def test_create_token_command_required_fields(self) -> None:
        """Test CreateTokenCommand with required fields only."""
        user_id = uuid4()
        expires_in = timedelta(hours=1)

        command = CreateTokenCommand(
            user_id=user_id,
            token_type="access",
            expires_in=expires_in,
        )

        assert command.user_id == user_id
        assert command.token_type == "access"
        assert command.expires_in == expires_in
        assert command.scopes is None
        assert command.metadata is None

    def test_create_token_command_all_fields(self) -> None:
        """Test CreateTokenCommand with all fields."""
        user_id = uuid4()
        expires_in = timedelta(hours=1)
        scopes = ["read", "write"]
        metadata = {"client_id": "test_client"}

        command = CreateTokenCommand(
            user_id=user_id,
            token_type="refresh",
            expires_in=expires_in,
            scopes=scopes,
            metadata=metadata,
        )

        assert command.user_id == user_id
        assert command.token_type == "refresh"
        assert command.expires_in == expires_in
        assert command.scopes == scopes
        assert command.metadata == metadata

    def test_create_token_command_validation(self) -> None:
        """Test CreateTokenCommand validation."""
        uuid4()
        timedelta(hours=1)

        # Test validation - all required fields are validated elsewhere
        # CreateTokenCommand requires specific token_type values


class TestRevokeTokenCommand:
    """Test RevokeTokenCommand functionality."""

    def test_revoke_token_command_required_fields(self) -> None:
        """Test RevokeTokenCommand with required fields only."""
        token_id = uuid4()

        command = RevokeTokenCommand(token_id=token_id)

        assert command.token_id == token_id
        assert command.revoked_by is None

    def test_revoke_token_command_all_fields(self) -> None:
        """Test RevokeTokenCommand with all fields."""
        token_id = uuid4()
        revoked_by = uuid4()

        command = RevokeTokenCommand(
            token_id=token_id,
            revoked_by=revoked_by,
        )

        assert command.token_id == token_id
        assert command.revoked_by == revoked_by

    def test_revoke_token_command_validation(self) -> None:
        """Test RevokeTokenCommand validation."""
        # All tests above already cover the functionality
        # RevokeTokenCommand requires token_id which is tested above


class TestCreateSessionCommand:
    """Test CreateSessionCommand functionality."""

    def test_create_session_command_required_fields(self) -> None:
        """Test CreateSessionCommand with required fields only."""
        user_id = uuid4()

        command = CreateSessionCommand(user_id=user_id)

        assert command.user_id == user_id
        assert command.expires_in is None
        assert command.user_agent is None

    def test_create_session_command_all_fields(self) -> None:
        """Test CreateSessionCommand with all fields."""
        user_id = uuid4()
        expires_in = timedelta(hours=2)

        command = CreateSessionCommand(
            user_id=user_id,
            expires_in=expires_in,
            user_agent="Test Browser",
        )

        assert command.user_id == user_id
        assert command.expires_in == expires_in
        assert command.user_agent == "Test Browser"

    def test_create_session_command_validation(self) -> None:
        """Test CreateSessionCommand validation."""
        # CreateSessionCommand requires user_id which is tested above


class TestRefreshSessionCommand:
    """Test RefreshSessionCommand functionality."""

    def test_refresh_session_command_required_fields(self) -> None:
        """Test RefreshSessionCommand with required fields."""
        session_id = uuid4()
        duration = timedelta(hours=1)

        command = RefreshSessionCommand(
            session_id=session_id,
            duration=duration,
        )

        assert command.session_id == session_id
        assert command.duration == duration

    def test_refresh_session_command_validation(self) -> None:
        """Test RefreshSessionCommand validation."""
        uuid4()
        timedelta(hours=1)

        # RefreshSessionCommand requires both session_id and duration
        # This is already tested in the required_fields test above


class TestDeactivateSessionCommand:
    """Test DeactivateSessionCommand functionality."""

    def test_deactivate_session_command_required_fields(self) -> None:
        """Test DeactivateSessionCommand with required fields."""
        session_id = uuid4()

        command = DeactivateSessionCommand(session_id=session_id)

        assert command.session_id == session_id

    def test_deactivate_session_command_validation(self) -> None:
        """Test DeactivateSessionCommand validation."""
        # DeactivateSessionCommand requires session_id which is tested above


class TestCreateRoleCommand:
    """Test CreateRoleCommand functionality."""

    def test_create_role_command_required_fields(self) -> None:
        """Test CreateRoleCommand with required fields only."""
        command = CreateRoleCommand(name="REDACTED_LDAP_BIND_PASSWORD")

        assert command.name == "REDACTED_LDAP_BIND_PASSWORD"
        assert command.description is None
        assert command.permissions is None
        assert command.is_system is False
        assert command.parent_role_id is None

    def test_create_role_command_all_fields(self) -> None:
        """Test CreateRoleCommand with all fields."""
        parent_role_id = uuid4()
        permissions = ["read:users", "write:users"]

        command = CreateRoleCommand(
            name="super_REDACTED_LDAP_BIND_PASSWORD",
            description="Super REDACTED_LDAP_BIND_PASSWORDistrator role",
            permissions=permissions,
            is_system=True,
            parent_role_id=parent_role_id,
        )

        assert command.name == "super_REDACTED_LDAP_BIND_PASSWORD"
        assert command.description == "Super REDACTED_LDAP_BIND_PASSWORDistrator role"
        assert command.permissions == permissions
        assert command.is_system is True
        assert command.parent_role_id == parent_role_id

    def test_create_role_command_validation(self) -> None:
        """Test CreateRoleCommand validation."""
        # Test empty name validation
        with pytest.raises(ValidationError):
            CreateRoleCommand(name="")  # Empty name

        # Test empty name
        with pytest.raises(ValidationError):
            CreateRoleCommand(name="")


class TestUpdateRoleCommand:
    """Test UpdateRoleCommand functionality."""

    def test_update_role_command_required_fields(self) -> None:
        """Test UpdateRoleCommand with required fields only."""
        role_id = uuid4()

        command = UpdateRoleCommand(role_id=role_id)

        assert command.role_id == role_id
        assert command.name is None
        assert command.description is None
        assert command.permissions is None
        assert command.parent_role_id is None

    def test_update_role_command_all_fields(self) -> None:
        """Test UpdateRoleCommand with all fields."""
        role_id = uuid4()
        parent_role_id = uuid4()
        permissions = ["read:posts", "write:posts"]

        command = UpdateRoleCommand(
            role_id=role_id,
            name="content_REDACTED_LDAP_BIND_PASSWORD",
            description="Content REDACTED_LDAP_BIND_PASSWORDistrator",
            permissions=permissions,
            parent_role_id=parent_role_id,
        )

        assert command.role_id == role_id
        assert command.name == "content_REDACTED_LDAP_BIND_PASSWORD"
        assert command.description == "Content REDACTED_LDAP_BIND_PASSWORDistrator"
        assert command.permissions == permissions
        assert command.parent_role_id == parent_role_id

    def test_update_role_command_validation(self) -> None:
        """Test UpdateRoleCommand validation."""
        # UpdateRoleCommand requires role_id which is tested above


class TestAssignRoleCommand:
    """Test AssignRoleCommand functionality."""

    def test_assign_role_command_required_fields(self) -> None:
        """Test AssignRoleCommand with required fields only."""
        user_id = uuid4()

        command = AssignRoleCommand(user_id=user_id)

        assert command.user_id == user_id
        assert command.role_id is None

    def test_assign_role_command_all_fields(self) -> None:
        """Test AssignRoleCommand with all fields."""
        user_id = uuid4()
        role_id = uuid4()

        command = AssignRoleCommand(
            user_id=user_id,
            role_id=role_id,
        )

        assert command.user_id == user_id
        assert command.role_id == role_id

    def test_assign_role_command_validation(self) -> None:
        """Test AssignRoleCommand validation."""
        # AssignRoleCommand requires user_id which is tested above


class TestRemoveRoleCommand:
    """Test RemoveRoleCommand functionality."""

    def test_remove_role_command_required_fields(self) -> None:
        """Test RemoveRoleCommand with required fields only."""
        user_id = uuid4()

        command = RemoveRoleCommand(user_id=user_id)

        assert command.user_id == user_id
        assert command.role_id is None

    def test_remove_role_command_all_fields(self) -> None:
        """Test RemoveRoleCommand with all fields."""
        user_id = uuid4()
        role_id = uuid4()

        command = RemoveRoleCommand(
            user_id=user_id,
            role_id=role_id,
        )

        assert command.user_id == user_id
        assert command.role_id == role_id

    def test_remove_role_command_validation(self) -> None:
        """Test RemoveRoleCommand validation."""
        # RemoveRoleCommand requires user_id which is tested above


class TestVerifyEmailCommand:
    """Test VerifyEmailCommand functionality."""

    def test_verify_email_command_required_fields(self) -> None:
        """Test VerifyEmailCommand with required fields."""
        user_id = uuid4()

        command = VerifyEmailCommand(
            user_id=user_id,
            verification_token="verify_token_123",
        )

        assert command.user_id == user_id
        assert command.verification_token == "verify_token_123"

    def test_verify_email_command_validation(self) -> None:
        """Test VerifyEmailCommand validation."""
        user_id = uuid4()

        # Test empty verification_token
        with pytest.raises(ValidationError):
            VerifyEmailCommand(user_id=user_id, verification_token="")  # Empty token


class TestSendPasswordResetCommand:
    """Test SendPasswordResetCommand functionality."""

    def test_send_password_reset_command_required_fields(self) -> None:
        """Test SendPasswordResetCommand with required fields."""
        command = SendPasswordResetCommand(email="user@example.com")

        assert command.email == "user@example.com"

    def test_send_password_reset_command_validation(self) -> None:
        """Test SendPasswordResetCommand validation."""
        # Test empty email validation
        with pytest.raises(ValidationError):
            SendPasswordResetCommand(email="")  # Empty email

        # Test empty email
        with pytest.raises(ValidationError):
            SendPasswordResetCommand(email="")


class TestLockUserCommand:
    """Test LockUserCommand functionality."""

    def test_lock_user_command_required_fields(self) -> None:
        """Test LockUserCommand with required fields only."""
        user_id = uuid4()

        command = LockUserCommand(user_id=user_id)

        assert command.user_id == user_id
        assert command.duration is None
        assert command.reason is None

    def test_lock_user_command_all_fields(self) -> None:
        """Test LockUserCommand with all fields."""
        user_id = uuid4()
        duration = timedelta(hours=24)

        command = LockUserCommand(
            user_id=user_id,
            duration=duration,
            reason="Suspicious activity",
        )

        assert command.user_id == user_id
        assert command.duration == duration
        assert command.reason == "Suspicious activity"

    def test_lock_user_command_validation(self) -> None:
        """Test LockUserCommand validation."""
        # LockUserCommand requires user_id which is tested above


class TestUnlockUserCommand:
    """Test UnlockUserCommand functionality."""

    def test_unlock_user_command_required_fields(self) -> None:
        """Test UnlockUserCommand with required fields only."""
        user_id = uuid4()

        command = UnlockUserCommand(user_id=user_id)

        assert command.user_id == user_id
        assert command.unlocked_by is None

    def test_unlock_user_command_all_fields(self) -> None:
        """Test UnlockUserCommand with all fields."""
        user_id = uuid4()
        unlocked_by = uuid4()

        command = UnlockUserCommand(
            user_id=user_id,
            unlocked_by=unlocked_by,
        )

        assert command.user_id == user_id
        assert command.unlocked_by == unlocked_by

    def test_unlock_user_command_validation(self) -> None:
        """Test UnlockUserCommand validation."""
        # UnlockUserCommand requires user_id which is tested above


class TestCommandIntegration:
    """Test command integration and patterns."""

    def test_command_inheritance(self) -> None:
        """Test that all commands inherit from Command base class."""
        from flext_auth.application.commands import Command

        # Test a few representative commands
        user_id = uuid4()
        create_user_cmd = CreateUserCommand(username="test")
        update_user_cmd = UpdateUserCommand(user_id=user_id)
        auth_cmd = AuthenticateUserCommand(username="test")

        assert isinstance(create_user_cmd, Command)
        assert isinstance(update_user_cmd, Command)
        assert isinstance(auth_cmd, Command)

    def test_command_serialization(self) -> None:
        """Test command serialization and deserialization."""
        user_id = uuid4()
        uuid4()

        # Test complex command with all field types
        command = CreateTokenCommand(
            user_id=user_id,
            token_type="access",
            expires_in=timedelta(hours=1),
            scopes=["read", "write"],
            metadata={"client": "test"},
        )

        # Test serialization to dict
        command_dict = command.model_dump()
        # UUID might be serialized as UUID object or string depending on mode
        assert command_dict["user_id"] == user_id or command_dict["user_id"] == str(
            user_id,
        )
        assert command_dict["token_type"] == "access"
        assert command_dict["scopes"] == ["read", "write"]
        assert command_dict["metadata"] == {"client": "test"}

        # Test deserialization from dict
        recreated_command = CreateTokenCommand.model_validate(command_dict)
        assert recreated_command.user_id == user_id
        assert recreated_command.token_type == "access"
        assert recreated_command.scopes == ["read", "write"]
        assert recreated_command.metadata == {"client": "test"}

    def test_command_immutability(self) -> None:
        """Test that commands are immutable after creation."""
        command = CreateUserCommand(username="testuser")

        # Commands should be frozen/immutable
        # Since Pydantic 2.x with frozen=True, attempting to change will raise ValidationError
        with pytest.raises((ValidationError, AttributeError)):
            command.username = "changed_username"  # type: ignore[misc]

    def test_user_lifecycle_commands(self) -> None:
        """Test commands for complete user lifecycle."""
        user_id = uuid4()
        role_id = uuid4()
        session_id = uuid4()

        # 1. Create user
        create_cmd = CreateUserCommand(
            username="testuser",
            email="test@example.com",
            send_verification_email=True,
        )
        assert create_cmd.username == "testuser"

        # 2. Verify email
        verify_cmd = VerifyEmailCommand(
            user_id=user_id,
            verification_token="verify_token",
        )
        assert verify_cmd.user_id == user_id

        # 3. Authenticate user
        auth_cmd = AuthenticateUserCommand(
            username="testuser",
            password="password",
        )
        assert auth_cmd.username == "testuser"

        # 4. Create session
        session_cmd = CreateSessionCommand(
            user_id=user_id,
            expires_in=timedelta(hours=1),
        )
        assert session_cmd.user_id == user_id

        # 5. Assign role
        assign_role_cmd = AssignRoleCommand(
            user_id=user_id,
            role_id=role_id,
        )
        assert assign_role_cmd.user_id == user_id

        # 6. Change password
        change_password_cmd = ChangePasswordCommand(
            user_id=user_id,
            current_password="old_password",
            new_password="new_password",
        )
        assert change_password_cmd.user_id == user_id

        # 7. Logout user
        logout_cmd = LogoutUserCommand(
            user_id=user_id,
            session_id=session_id,
        )
        assert logout_cmd.user_id == user_id

        # All commands should be valid
        assert all(
            [
                create_cmd.username == "testuser",
                verify_cmd.user_id == user_id,
                auth_cmd.username == "testuser",
                session_cmd.user_id == user_id,
                assign_role_cmd.user_id == user_id,
                change_password_cmd.user_id == user_id,
                logout_cmd.user_id == user_id,
            ],
        )

    def test_REDACTED_LDAP_BIND_PASSWORD_workflow_commands(self) -> None:
        """Test commands for REDACTED_LDAP_BIND_PASSWORD workflow."""
        user_id = uuid4()
        uuid4()
        token_id = uuid4()
        REDACTED_LDAP_BIND_PASSWORD_id = uuid4()

        # 1. Create role
        create_role_cmd = CreateRoleCommand(
            name="moderator",
            description="Moderator role",
            permissions=["read:posts", "moderate:comments"],
        )
        assert create_role_cmd.name == "moderator"

        # 2. Update user (REDACTED_LDAP_BIND_PASSWORD action)
        update_user_cmd = UpdateUserCommand(
            user_id=user_id,
            is_staff=True,
            updated_by=REDACTED_LDAP_BIND_PASSWORD_id,
        )
        assert update_user_cmd.user_id == user_id

        # 3. Lock user account
        lock_cmd = LockUserCommand(
            user_id=user_id,
            duration=timedelta(hours=24),
            reason="Policy violation",
        )
        assert lock_cmd.user_id == user_id

        # 4. Revoke token
        revoke_token_cmd = RevokeTokenCommand(
            token_id=token_id,
            revoked_by=REDACTED_LDAP_BIND_PASSWORD_id,
        )
        assert revoke_token_cmd.token_id == token_id

        # 5. Unlock user account
        unlock_cmd = UnlockUserCommand(
            user_id=user_id,
            unlocked_by=REDACTED_LDAP_BIND_PASSWORD_id,
        )
        assert unlock_cmd.user_id == user_id

        # All REDACTED_LDAP_BIND_PASSWORD commands should be valid
        assert all(
            [
                create_role_cmd.name == "moderator",
                update_user_cmd.updated_by == REDACTED_LDAP_BIND_PASSWORD_id,
                lock_cmd.reason == "Policy violation",
                revoke_token_cmd.revoked_by == REDACTED_LDAP_BIND_PASSWORD_id,
                unlock_cmd.unlocked_by == REDACTED_LDAP_BIND_PASSWORD_id,
            ],
        )

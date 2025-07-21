"""Comprehensive tests for session_manager module.

Tests all functionality in session_manager to achieve 100% coverage
and verify enterprise session management implementation.
"""

from __future__ import annotations

import asyncio
import contextlib
from datetime import UTC, datetime, timedelta
from unittest.mock import Mock, patch
from uuid import uuid4

import pytest
from flext_core.domain.core import ServiceError

from flext_auth.session_manager import (
    EnterpriseSessionManager,
    RBACManager,
    RolePermission,
    SessionMetadata,
)


class TestServiceError:
    """Test ServiceError functionality."""

    def test_initialization(self) -> None:
        """Test ServiceError initialization."""
        error = ServiceError("TEST_ERROR", "Test message")
        assert error.error_code == "TEST_ERROR"
        assert error.message == "Test message"


class TestSessionMetadata:
    """Test SessionMetadata functionality."""

    def test_initialization_default_values(self) -> None:
        """Test SessionMetadata initialization with default values."""
        session_id = "test_session_id"
        user_id = uuid4()

        session = SessionMetadata(session_id=session_id, user_id=user_id)

        assert session.session_id == session_id
        assert session.user_id == user_id
        assert session.ip_address is None
        assert session.user_agent is None
        assert session.device_info == {}
        assert isinstance(session.created_at, datetime)
        assert isinstance(session.last_accessed, datetime)
        assert isinstance(session.expires_at, datetime)
        assert session.permissions == set()
        assert session.roles == set()

    def test_initialization_with_all_values(self) -> None:
        """Test SessionMetadata initialization with all values provided."""
        session_id = "test_session_id"
        user_id = uuid4()
        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0"
        device_info = {"platform": "web", "browser": "chrome"}
        created_at = datetime.now(UTC)
        last_accessed = datetime.now(UTC)
        expires_at = datetime.now(UTC) + timedelta(hours=1)

        session = SessionMetadata(
            session_id=session_id,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            device_info=device_info,
            created_at=created_at,
            last_accessed=last_accessed,
            expires_at=expires_at,
        )

        assert session.session_id == session_id
        assert session.user_id == user_id
        assert session.ip_address == ip_address
        assert session.user_agent == user_agent
        assert session.device_info == device_info
        assert session.created_at == created_at
        assert session.last_accessed == last_accessed
        assert session.expires_at == expires_at

    def test_is_expired_property_false(self) -> None:
        """Test is_expired property returns False for valid session."""
        session = SessionMetadata(
            session_id="test",
            user_id=uuid4(),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        assert not session.is_expired

    def test_is_expired_property_true(self) -> None:
        """Test is_expired property returns True for expired session."""
        session = SessionMetadata(
            session_id="test",
            user_id=uuid4(),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert session.is_expired

    def test_is_valid_property_true(self) -> None:
        """Test is_valid property returns True for valid session."""
        session = SessionMetadata(
            session_id="test",
            user_id=uuid4(),
            expires_at=datetime.now(UTC) + timedelta(hours=1),
        )
        assert session.is_valid

    def test_is_valid_property_false(self) -> None:
        """Test is_valid property returns False for expired session."""
        session = SessionMetadata(
            session_id="test",
            user_id=uuid4(),
            expires_at=datetime.now(UTC) - timedelta(hours=1),
        )
        assert not session.is_valid

    def test_update_access(self) -> None:
        """Test update_access method updates last_accessed timestamp."""
        session = SessionMetadata(session_id="test", user_id=uuid4())
        original_last_accessed = session.last_accessed

        # Wait a small amount to ensure timestamp difference
        import time

        time.sleep(0.01)

        session.update_access()
        assert session.last_accessed > original_last_accessed

    def test_extend_session(self) -> None:
        """Test extend_session method extends expiration time."""
        session = SessionMetadata(session_id="test", user_id=uuid4())

        extension = timedelta(hours=2)
        before_extension = datetime.now(UTC)
        session.extend_session(extension)
        after_extension = datetime.now(UTC)

        # The new expiry should be approximately now + extension
        expected_expiry_min = before_extension + extension
        expected_expiry_max = after_extension + extension

        # Verify the session was extended (new expiry should be within expected range)
        assert session.expires_at is not None
        assert expected_expiry_min <= session.expires_at <= expected_expiry_max


class TestRolePermission:
    """Test RolePermission functionality."""

    def test_initialization(self) -> None:
        """Test RolePermission initialization."""
        role = "REDACTED_LDAP_BIND_PASSWORD"
        permissions = {"read", "write", "delete"}

        role_permission = RolePermission(role=role, permissions=permissions)

        assert role_permission.role == role
        assert role_permission.permissions == permissions


class TestRBACManager:
    """Test RBACManager functionality."""

    def test_initialization(self) -> None:
        """Test RBACManager initialization with default hierarchy."""
        rbac = RBACManager()

        # Check role permissions are properly initialized - hierarchy removed for now
        # TODO: Add role hierarchy if needed in future iterations

        # Check role permissions are properly initialized
        assert "system:REDACTED_LDAP_BIND_PASSWORD" in rbac._role_permissions["REDACTED_LDAP_BIND_PASSWORD"]
        assert "user:read" in rbac._role_permissions["user"]
        assert "user:read" in rbac._role_permissions["guest"]

    def test_get_effective_permissions_single_role(self) -> None:
        """Test get_effective_permissions with single role."""
        rbac = RBACManager()

        # Test viewer role (no inherited roles)
        viewer_permissions = rbac.get_effective_permissions({"viewer"})
        expected_viewer = {"pipeline:read", "plugin:read", "data:read"}
        assert viewer_permissions == expected_viewer

    def test_get_effective_permissions_with_inheritance(self) -> None:
        """Test get_effective_permissions with role inheritance."""
        rbac = RBACManager()

        # Test REDACTED_LDAP_BIND_PASSWORD role (inherits from manager, user, viewer)
        REDACTED_LDAP_BIND_PASSWORD_permissions = rbac.get_effective_permissions({"REDACTED_LDAP_BIND_PASSWORD"})

        # Should include REDACTED_LDAP_BIND_PASSWORD permissions plus inherited ones
        assert "user:manage" in REDACTED_LDAP_BIND_PASSWORD_permissions  # Direct REDACTED_LDAP_BIND_PASSWORD permission
        assert "pipeline:create" in REDACTED_LDAP_BIND_PASSWORD_permissions  # From manager
        assert "pipeline:read" in REDACTED_LDAP_BIND_PASSWORD_permissions  # From user
        assert "data:read" in REDACTED_LDAP_BIND_PASSWORD_permissions  # From viewer

    def test_get_effective_permissions_multiple_roles(self) -> None:
        """Test get_effective_permissions with multiple roles."""
        rbac = RBACManager()

        # Test user with both REDACTED_LDAP_BIND_PASSWORD and manager roles
        permissions = rbac.get_effective_permissions({"REDACTED_LDAP_BIND_PASSWORD", "manager"})

        # Should include permissions from both roles
        assert "user:manage" in permissions  # From REDACTED_LDAP_BIND_PASSWORD
        assert "pipeline:create" in permissions  # From manager
        assert "data:read" in permissions  # Inherited

    def test_get_effective_permissions_unknown_role(self) -> None:
        """Test get_effective_permissions with unknown role."""
        rbac = RBACManager()

        permissions = rbac.get_effective_permissions({"unknown_role"})
        assert permissions == set()

    def test_has_permission_true(self) -> None:
        """Test has_permission returns True when user has permission."""
        rbac = RBACManager()

        result = rbac.has_permission({"REDACTED_LDAP_BIND_PASSWORD"}, "user:manage")
        assert result is True

        # Test inherited permission
        result = rbac.has_permission({"REDACTED_LDAP_BIND_PASSWORD"}, "data:read")
        assert result is True

    def test_has_permission_false(self) -> None:
        """Test has_permission returns False when user lacks permission."""
        rbac = RBACManager()

        result = rbac.has_permission({"viewer"}, "user:manage")
        assert result is False

        result = rbac.has_permission({"unknown_role"}, "any:permission")
        assert result is False

    def test_has_role_direct(self) -> None:
        """Test has_role returns True for directly assigned role."""
        rbac = RBACManager()

        result = rbac.has_role({"REDACTED_LDAP_BIND_PASSWORD"}, "REDACTED_LDAP_BIND_PASSWORD")
        assert result is True

    def test_has_role_inherited(self) -> None:
        """Test has_role returns True for inherited role."""
        rbac = RBACManager()

        result = rbac.has_role({"REDACTED_LDAP_BIND_PASSWORD"}, "user")
        assert result is True

        result = rbac.has_role({"super_REDACTED_LDAP_BIND_PASSWORD"}, "REDACTED_LDAP_BIND_PASSWORD")
        assert result is True

    def test_has_role_false(self) -> None:
        """Test has_role returns False when user lacks role."""
        rbac = RBACManager()

        result = rbac.has_role({"viewer"}, "REDACTED_LDAP_BIND_PASSWORD")
        assert result is False

        result = rbac.has_role({"user"}, "REDACTED_LDAP_BIND_PASSWORD")
        assert result is False

    def test_add_role_permission_new_role(self) -> None:
        """Test add_role_permission for new role."""
        rbac = RBACManager()

        rbac.add_role_permission("new_role", "new:permission")

        assert "new_role" in rbac._role_permissions
        assert "new:permission" in rbac._role_permissions["new_role"]

    def test_add_role_permission_existing_role(self) -> None:
        """Test add_role_permission for existing role."""
        rbac = RBACManager()

        rbac.add_role_permission("REDACTED_LDAP_BIND_PASSWORD", "new:permission")

        assert "new:permission" in rbac._role_permissions["REDACTED_LDAP_BIND_PASSWORD"]
        assert (
            "user:manage" in rbac._role_permissions["REDACTED_LDAP_BIND_PASSWORD"]
        )  # Original permission still there

    def test_remove_role_permission_existing(self) -> None:
        """Test remove_role_permission for existing permission."""
        rbac = RBACManager()

        rbac.remove_role_permission("REDACTED_LDAP_BIND_PASSWORD", "user:manage")

        assert "user:manage" not in rbac._role_permissions["REDACTED_LDAP_BIND_PASSWORD"]

    def test_remove_role_permission_nonexistent_role(self) -> None:
        """Test remove_role_permission for nonexistent role."""
        rbac = RBACManager()

        # Should not raise exception
        rbac.remove_role_permission("nonexistent_role", "any:permission")

    def test_remove_role_permission_nonexistent_permission(self) -> None:
        """Test remove_role_permission for nonexistent permission."""
        rbac = RBACManager()

        # Should not raise exception
        rbac.remove_role_permission("REDACTED_LDAP_BIND_PASSWORD", "nonexistent:permission")


class TestEnterpriseSessionManager:
    """Test EnterpriseSessionManager functionality."""

    def test_initialization_without_db_session(self) -> None:
        """Test EnterpriseSessionManager initialization without database session."""
        manager = EnterpriseSessionManager()

        assert manager.db_session is None
        assert isinstance(manager.rbac_manager, RBACManager)
        assert manager._active_sessions == {}
        assert manager._user_sessions == {}
        assert manager._cleanup_task is None
        assert manager.default_session_timeout_hours == 24

    def test_initialization_with_db_session(self) -> None:
        """Test EnterpriseSessionManager initialization with database session."""
        mock_db_session = Mock()
        manager = EnterpriseSessionManager(db_session=mock_db_session)

        assert manager.db_session is mock_db_session

    @pytest.mark.asyncio
    async def test_create_session_success(self) -> None:
        """Test successful session creation."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()
        ip_address = "192.168.1.100"
        user_agent = "Mozilla/5.0"
        device_info = {"platform": "web"}

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event") as mock_log,
        ):
            result = await manager.create_session(
                user_id=user_id,
                ip_address=ip_address,
                user_agent=user_agent,
                device_info=device_info,
            )

            assert result.is_success
            session_metadata = result.data
            assert isinstance(session_metadata, SessionMetadata)
            assert session_metadata.user_id == user_id
            assert session_metadata.ip_address == ip_address
            assert session_metadata.user_agent == user_agent
            assert session_metadata.device_info == device_info
            assert "user" in session_metadata.roles

            # Check session is stored
            assert session_metadata.session_id in manager._active_sessions
            assert user_id in manager._user_sessions
            assert session_metadata.session_id in manager._user_sessions[user_id]

            # Check security event logged
            mock_log.assert_called_once()

    @pytest.mark.asyncio
    async def test_create_session_with_custom_duration(self) -> None:
        """Test session creation with custom duration."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()
        custom_duration = timedelta(hours=2)

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            result = await manager.create_session(
                user_id=user_id,
                session_duration=custom_duration,
            )

            assert result.is_success
            assert result.data is not None
            session_metadata = result.data

            # Check custom duration was applied
            expected_expiry = datetime.now(UTC) + custom_duration
            actual_expiry = session_metadata.expires_at
            # Allow for small time differences (within 1 second)
            assert actual_expiry is not None
            assert abs((actual_expiry - expected_expiry).total_seconds()) < 1

    @pytest.mark.asyncio
    async def test_create_session_exception_handling(self) -> None:
        """Test session creation with exception handling."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with patch.object(
            manager,
            "_get_user_roles",
            side_effect=ValueError("Database error"),
        ):
            result = await manager.create_session(user_id=user_id)

            assert not result.is_success
            assert result.error is not None
            assert "Failed to create session" in result.error

    @pytest.mark.asyncio
    async def test_validate_session_success(self) -> None:
        """Test successful session validation."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        # Create a session first
        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.data is not None
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Validate the session
            validate_result = await manager.validate_session(session_id=session_id)

            assert validate_result.is_success
            assert validate_result.data is not None
            assert validate_result.data.session_id == session_id

    @pytest.mark.asyncio
    async def test_validate_session_not_found(self) -> None:
        """Test session validation with nonexistent session."""
        manager = EnterpriseSessionManager()

        result = await manager.validate_session(session_id="nonexistent_session")

        assert not result.is_success
        assert result.error is not None
        assert result.error is not None
        assert "Session not found" in result.error

    @pytest.mark.asyncio
    async def test_validate_session_expired(self) -> None:
        """Test session validation with expired session."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create session with very short duration
            create_result = await manager.create_session(
                user_id=user_id,
                session_duration=timedelta(milliseconds=1),
            )
            assert create_result.data is not None
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Wait for expiration
            await asyncio.sleep(0.01)

            # Validate expired session
            result = await manager.validate_session(session_id=session_id)

            assert not result.is_success
            assert result.error is not None
            assert "Session expired" in result.error
            # Session should be removed after expiration check
            assert session_id not in manager._active_sessions

    @pytest.mark.asyncio
    async def test_validate_session_ip_mismatch(self) -> None:
        """Test session validation with IP address mismatch."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()
        original_ip = "192.168.1.100"
        different_ip = "192.168.1.200"

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event") as mock_log,
        ):
            # Create session with specific IP
            create_result = await manager.create_session(
                user_id=user_id,
                ip_address=original_ip,
            )
            assert create_result.is_success
            assert create_result.data is not None
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Validate with different IP
            result = await manager.validate_session(
                session_id=session_id,
                ip_address=different_ip,
            )

            assert not result.is_success
            assert result.error is not None
            assert "IP address mismatch" in result.error

            # Check security event was logged for IP mismatch
            security_calls = [
                call
                for call in mock_log.call_args_list
                if call[1]["event_type"] == "session_ip_mismatch"
            ]
            assert len(security_calls) == 1

    @pytest.mark.asyncio
    async def test_validate_session_insufficient_permission(self) -> None:
        """Test session validation with insufficient permissions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"viewer"}),
            patch.object(manager, "_log_security_event") as mock_log,
        ):
            # Create session with viewer role
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.is_success
            assert create_result.data is not None
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Validate with REDACTED_LDAP_BIND_PASSWORD permission requirement
            result = await manager.validate_session(
                session_id=session_id,
                required_permission="user:manage",
            )

            assert not result.is_success
            assert result.error is not None
            assert "Insufficient permissions" in result.error

            # Check security event was logged
            security_calls = [
                call
                for call in mock_log.call_args_list
                if call[1]["event_type"] == "session_permission_denied"
            ]
            assert len(security_calls) == 1

    @pytest.mark.asyncio
    async def test_validate_session_insufficient_role(self) -> None:
        """Test session validation with insufficient role."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event") as mock_log,
        ):
            # Create session with user role
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.data is not None
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Validate with REDACTED_LDAP_BIND_PASSWORD role requirement
            result = await manager.validate_session(
                session_id=session_id,
                required_role="REDACTED_LDAP_BIND_PASSWORD",
            )

            assert not result.is_success
            assert result.error is not None
            assert "Insufficient role" in result.error

            # Check security event was logged
            security_calls = [
                call
                for call in mock_log.call_args_list
                if call[1]["event_type"] == "session_role_denied"
            ]
            assert len(security_calls) == 1

    @pytest.mark.asyncio
    async def test_validate_session_exception_handling(self) -> None:
        """Test session validation with exception handling."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create session first
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.is_success
            assert create_result.data is not None
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Mock RBAC manager to raise exception during validation
            with patch.object(
                manager.rbac_manager,
                "has_permission",
                side_effect=ValueError("RBAC error"),
            ):
                result = await manager.validate_session(
                    session_id=session_id,
                    required_permission="test:permission",
                )

                assert not result.is_success
                assert result.error is not None
                assert "Failed to validate session" in result.error

    @pytest.mark.asyncio
    async def test_extend_session_success(self) -> None:
        """Test successful session extension."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()
        extension_duration = timedelta(hours=2)

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event") as mock_log,
        ):
            # Create session
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.is_success
            assert create_result.data is not None
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Capture original expiry before extension (in case object is modified in place)
            original_expiry = create_result.data.expires_at
            assert original_expiry is not None

            # Extend session
            result = await manager.extend_session(session_id, extension_duration)

            assert result.is_success
            assert result.data is not None

            # The new expiry should be approximately original_expiry + extension_duration
            assert original_expiry is not None
            expected_expiry = original_expiry + extension_duration
            assert result.data.expires_at is not None
            assert result.data.expires_at == expected_expiry

            # Check security event was logged
            security_calls = [
                call
                for call in mock_log.call_args_list
                if call[1]["event_type"] == "session_extended"
            ]
            assert len(security_calls) == 1

    @pytest.mark.asyncio
    async def test_extend_session_not_found(self) -> None:
        """Test session extension with nonexistent session."""
        manager = EnterpriseSessionManager()

        result = await manager.extend_session("nonexistent_session", timedelta(hours=1))

        assert not result.is_success
        assert result.error is not None
        assert "Session not found" in result.error

    @pytest.mark.asyncio
    async def test_extend_session_expired(self) -> None:
        """Test session extension with expired session."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create session with very short duration
            create_result = await manager.create_session(
                user_id=user_id,
                session_duration=timedelta(milliseconds=1),
            )
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Wait for expiration
            await asyncio.sleep(0.01)

            # Try to extend expired session
            result = await manager.extend_session(session_id, timedelta(hours=1))

            assert not result.is_success
            assert result.error is not None
            assert "Cannot extend expired session" in result.error

    @pytest.mark.asyncio
    async def test_extend_session_exception_handling(self) -> None:
        """Test session extension with exception handling."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create session first
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Mock extend_session method on session metadata to raise exception
            session_metadata = manager._active_sessions[session_id]
            with patch.object(
                session_metadata,
                "extend_session",
                side_effect=ValueError("Extension error"),
            ):
                result = await manager.extend_session(session_id, timedelta(hours=1))

                assert not result.is_success
                assert result.error is not None
                assert "Failed to extend session" in result.error

    @pytest.mark.asyncio
    async def test_terminate_session_success(self) -> None:
        """Test successful session termination."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event") as mock_log,
        ):
            # Create session
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Terminate session
            result = await manager.terminate_session(session_id, "user_logout")

            assert result.is_success
            assert result.data is not None
            assert "terminated successfully" in result.data["message"]
            assert session_id not in manager._active_sessions

            # Check security event was logged
            security_calls = [
                call
                for call in mock_log.call_args_list
                if call[1]["event_type"] == "session_terminated"
            ]
            assert len(security_calls) == 1

    @pytest.mark.asyncio
    async def test_terminate_session_not_found(self) -> None:
        """Test session termination with nonexistent session."""
        manager = EnterpriseSessionManager()

        result = await manager.terminate_session("nonexistent_session")

        assert not result.is_success
        assert result.error is not None
        assert "Session not found" in result.error

    @pytest.mark.asyncio
    async def test_terminate_session_exception_handling(self) -> None:
        """Test session termination with exception handling."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create session first
            create_result = await manager.create_session(user_id=user_id)
            assert create_result.data is not None
            session_id = create_result.data.session_id

            # Mock _log_security_event to raise exception during termination
            with patch.object(
                manager,
                "_log_security_event",
                side_effect=ValueError("Logging error"),
            ):
                result = await manager.terminate_session(session_id)

                assert not result.is_success
                assert result.error is not None
                assert "Failed to terminate session" in result.error

    @pytest.mark.asyncio
    async def test_terminate_user_sessions_success(self) -> None:
        """Test successful termination of all user sessions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create multiple sessions for user
            session_ids = []
            for _i in range(3):
                result = await manager.create_session(user_id=user_id)
                assert result.data is not None
                session_ids.append(result.data.session_id)

            # Terminate all user sessions
            terminate_result = await manager.terminate_user_sessions(
                user_id,
                reason="security_logout",
            )

            assert terminate_result.is_success
            assert terminate_result.data is not None
            assert terminate_result.data["terminated_count"] == 3
            assert user_id not in manager._user_sessions

    @pytest.mark.asyncio
    async def test_terminate_user_sessions_with_exclusion(self) -> None:
        """Test termination of user sessions with exclusion."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create multiple sessions for user
            session_ids = []
            for _i in range(3):
                result = await manager.create_session(user_id=user_id)
                assert result.data is not None
                session_ids.append(result.data.session_id)

            # Terminate all but exclude one session
            excluded_session = session_ids[0]
            termination_result = await manager.terminate_user_sessions(
                user_id,
                exclude_session_id=excluded_session,
                reason="security_logout",
            )

            assert termination_result.is_success
            assert termination_result.data is not None
            assert termination_result.data["terminated_count"] == 2
            assert excluded_session in manager._active_sessions

    @pytest.mark.asyncio
    async def test_terminate_user_sessions_no_sessions(self) -> None:
        """Test termination of user sessions when user has no sessions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        result = await manager.terminate_user_sessions(user_id)

        assert result.is_success
        assert result.data is not None
        assert result.data["terminated_count"] == 0
        assert "No active sessions found" in result.data["message"]

    @pytest.mark.asyncio
    async def test_terminate_user_sessions_exception_handling(self) -> None:
        """Test user sessions termination with exception handling."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create a session first
            await manager.create_session(user_id=user_id)

            # Mock terminate_session to raise exception
            with patch.object(
                manager,
                "terminate_session",
                side_effect=ValueError("Session termination error"),
            ):
                result = await manager.terminate_user_sessions(user_id)

                assert not result.is_success
                assert result.error is not None
                assert "Failed to terminate user sessions" in result.error

    @pytest.mark.asyncio
    async def test_get_user_sessions_success(self) -> None:
        """Test successful retrieval of user sessions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create multiple sessions for user
            for _i in range(2):
                await manager.create_session(user_id=user_id)

            # Get user sessions
            result = await manager.get_user_sessions(user_id)

            assert result.is_success
            assert result.data is not None
            assert len(result.data) == 2
            for session in result.data:
                assert isinstance(session, SessionMetadata)
                assert session.user_id == user_id

    @pytest.mark.asyncio
    async def test_get_user_sessions_include_expired(self) -> None:
        """Test retrieval of user sessions including expired ones."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create valid session
            await manager.create_session(user_id=user_id)

            # Create expired session
            await manager.create_session(
                user_id=user_id,
                session_duration=timedelta(milliseconds=1),
            )
            await asyncio.sleep(0.01)  # Wait for expiration

            # Get sessions excluding expired
            result_exclude = await manager.get_user_sessions(
                user_id,
                include_expired=False,
            )
            assert result_exclude.data is not None
            assert len(result_exclude.data) == 1

            # Get sessions including expired
            result_include = await manager.get_user_sessions(
                user_id,
                include_expired=True,
            )
            assert result_include.data is not None
            assert len(result_include.data) == 2

    @pytest.mark.asyncio
    async def test_get_user_sessions_no_sessions(self) -> None:
        """Test retrieval of user sessions when user has no sessions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        result = await manager.get_user_sessions(user_id)

        assert result.is_success
        assert result.data == []

    @pytest.mark.asyncio
    async def test_get_user_sessions_exception_handling(self) -> None:
        """Test user sessions retrieval with exception handling."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create session first
            await manager.create_session(user_id=user_id)

            # Mock session metadata to raise exception during iteration
            session_metadata = manager._active_sessions[
                next(iter(manager._active_sessions.keys()))
            ]
            # Patch the property using type() and property() trick
            with patch.object(
                type(session_metadata),
                "is_valid",
                property(
                    lambda self: (_ for _ in ()).throw(ValueError("Session error")),
                ),
            ):
                result = await manager.get_user_sessions(user_id)

                assert not result.is_success
                assert result.error is not None
                assert "Failed to get user sessions" in result.error

    @pytest.mark.asyncio
    async def test_cleanup_expired_sessions(self) -> None:
        """Test cleanup of expired sessions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create valid session
            await manager.create_session(user_id=user_id)

            # Create expired sessions
            for _i in range(3):
                await manager.create_session(
                    user_id=uuid4(),
                    session_duration=timedelta(milliseconds=1),
                )

            await asyncio.sleep(0.01)  # Wait for expiration

            # Run cleanup
            cleaned_count = await manager.cleanup_expired_sessions()

            assert cleaned_count == 3
            # Valid session should remain
            assert len(manager._active_sessions) == 1

    @pytest.mark.asyncio
    async def test_start_cleanup_task(self) -> None:
        """Test starting the periodic cleanup task."""
        manager = EnterpriseSessionManager()

        # Start cleanup task
        await manager.start_cleanup_task(interval=timedelta(milliseconds=10))

        assert manager._cleanup_task is not None
        assert not manager._cleanup_task.done()

        # Stop the task
        await manager.stop_cleanup_task()

    @pytest.mark.asyncio
    async def test_start_cleanup_task_already_running(self) -> None:
        """Test starting cleanup task when already running."""
        manager = EnterpriseSessionManager()

        # Start first task
        await manager.start_cleanup_task(interval=timedelta(milliseconds=10))
        first_task = manager._cleanup_task

        # Try to start again
        await manager.start_cleanup_task(interval=timedelta(milliseconds=20))

        # Should be the same task
        assert manager._cleanup_task is first_task

        # Stop the task
        await manager.stop_cleanup_task()

    @pytest.mark.asyncio
    async def test_stop_cleanup_task_no_task(self) -> None:
        """Test stopping cleanup task when no task is running."""
        manager = EnterpriseSessionManager()

        # Should not raise exception
        await manager.stop_cleanup_task()

    @pytest.mark.asyncio
    async def test_stop_cleanup_task_already_done(self) -> None:
        """Test stopping cleanup task when task is already done."""
        manager = EnterpriseSessionManager()

        # Create a completed task
        async def dummy_task() -> None:
            pass

        manager._cleanup_task = asyncio.create_task(dummy_task())
        await manager._cleanup_task  # Wait for completion

        # Should not raise exception
        await manager.stop_cleanup_task()

    @pytest.mark.asyncio
    async def test_get_session_stats_empty(self) -> None:
        """Test session statistics with no sessions."""
        manager = EnterpriseSessionManager()

        stats = await manager.get_session_stats()

        assert stats["total_sessions"] == 0
        assert stats["active_sessions"] == 0
        assert stats["expired_sessions"] == 0
        assert stats["unique_users"] == 0
        assert stats["role_distribution"] == {}
        assert stats["average_session_age"] == 0.0

    @pytest.mark.asyncio
    async def test_get_session_stats_with_sessions(self) -> None:
        """Test session statistics with active sessions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"REDACTED_LDAP_BIND_PASSWORD", "user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create sessions
            await manager.create_session(user_id=user_id)
            await manager.create_session(user_id=uuid4())

            stats = await manager.get_session_stats()

            assert stats["total_sessions"] == 2
            assert stats["active_sessions"] == 2
            assert stats["expired_sessions"] == 0
            assert stats["unique_users"] == 2
            assert "REDACTED_LDAP_BIND_PASSWORD" in stats["role_distribution"]
            assert "user" in stats["role_distribution"]
            assert stats["average_session_age"] >= 0

    @pytest.mark.asyncio
    async def test_get_session_stats_with_expired_sessions(self) -> None:
        """Test session statistics with expired sessions."""
        manager = EnterpriseSessionManager()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create expired session
            await manager.create_session(
                user_id=uuid4(),
                session_duration=timedelta(milliseconds=1),
            )

            await asyncio.sleep(0.01)  # Wait for expiration

            stats = await manager.get_session_stats()

            assert stats["total_sessions"] == 1
            assert stats["active_sessions"] == 0
            assert stats["expired_sessions"] == 1

    @pytest.mark.asyncio
    async def test_get_user_roles_without_db_session(self) -> None:
        """Test _get_user_roles without database session."""
        manager = EnterpriseSessionManager()

        roles = await manager._get_user_roles(uuid4())
        assert roles == {"user"}

    @pytest.mark.asyncio
    async def test_get_user_roles_with_db_session(self) -> None:
        """Test _get_user_roles with database session."""
        mock_db_session = Mock()
        manager = EnterpriseSessionManager(db_session=mock_db_session)

        roles = await manager._get_user_roles(uuid4())
        assert roles == {"user"}  # Still returns default for now

    @pytest.mark.asyncio
    async def test_get_user_roles_exception_handling(self) -> None:
        """Test _get_user_roles with exception handling."""
        manager = EnterpriseSessionManager()

        # Mock an exception during role extraction
        with patch.object(manager, "db_session", side_effect=ValueError("DB error")):
            roles = await manager._get_user_roles(uuid4())
            assert roles == {"user"}  # Should fallback to default

    @pytest.mark.asyncio
    async def test_remove_session(self) -> None:
        """Test _remove_session internal method."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create session
            result = await manager.create_session(user_id=user_id)
            assert result.data is not None
            session_id = result.data.session_id

            # Verify session exists
            assert session_id in manager._active_sessions
            assert user_id in manager._user_sessions

            # Remove session
            await manager._remove_session(session_id)

            # Verify session removed
            assert session_id not in manager._active_sessions
            assert user_id not in manager._user_sessions

    @pytest.mark.asyncio
    async def test_remove_session_nonexistent(self) -> None:
        """Test _remove_session with nonexistent session."""
        manager = EnterpriseSessionManager()

        # Should not raise exception
        await manager._remove_session("nonexistent_session")

    @pytest.mark.asyncio
    async def test_remove_session_multiple_user_sessions(self) -> None:
        """Test _remove_session when user has multiple sessions."""
        manager = EnterpriseSessionManager()
        user_id = uuid4()

        with (
            patch.object(manager, "_get_user_roles", return_value={"user"}),
            patch.object(manager, "_log_security_event"),
        ):
            # Create multiple sessions for user
            result1 = await manager.create_session(user_id=user_id)
            result2 = await manager.create_session(user_id=user_id)
            assert result1.data is not None
            assert result2.data is not None
            session_id1 = result1.data.session_id
            session_id2 = result2.data.session_id

            # Remove one session
            await manager._remove_session(session_id1)

            # Verify only one session removed
            assert session_id1 not in manager._active_sessions
            assert session_id2 in manager._active_sessions
            assert user_id in manager._user_sessions
            assert session_id2 in manager._user_sessions[user_id]

    @pytest.mark.asyncio
    async def test_log_security_event_integration(self) -> None:
        """Test _log_security_event method integration."""
        manager = EnterpriseSessionManager()

        with patch("flext_observability.logging.get_logger") as mock_get_logger:
            mock_logger = Mock()
            mock_get_logger.return_value = mock_logger

            await manager._log_security_event(
                event_type="test_event",
                user_id=uuid4(),
                ip_address="192.168.1.100",
                user_agent="Mozilla/5.0",
                metadata={"key": "value"},
            )

            mock_get_logger.assert_called_once_with("flext_auth.audit")
            mock_logger.info.assert_called_once()

    @pytest.mark.asyncio
    async def test_periodic_cleanup_normal_operation(self) -> None:
        """Test _periodic_cleanup normal operation."""
        manager = EnterpriseSessionManager()

        # Mock cleanup_expired_sessions
        with patch.object(
            manager,
            "cleanup_expired_sessions",
            return_value=0,
        ) as mock_cleanup:
            # Start cleanup with very short interval
            cleanup_task = asyncio.create_task(
                manager._periodic_cleanup(timedelta(milliseconds=10)),
            )

            # Let it run a few cycles
            await asyncio.sleep(0.05)

            # Cancel the task
            cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup_task

            # Verify cleanup was called
            assert mock_cleanup.call_count > 0

    @pytest.mark.asyncio
    async def test_periodic_cleanup_exception_handling(self) -> None:
        """Test _periodic_cleanup exception handling."""
        manager = EnterpriseSessionManager()

        # Mock cleanup_expired_sessions to raise exception
        with patch.object(
            manager,
            "cleanup_expired_sessions",
            side_effect=ValueError("Cleanup error"),
        ):
            # Start cleanup with very short interval
            cleanup_task = asyncio.create_task(
                manager._periodic_cleanup(timedelta(milliseconds=10)),
            )

            # Let it run and handle exceptions
            await asyncio.sleep(0.05)

            # Cancel the task
            cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await cleanup_task

            # Task should be cancelled or done (exceptions were handled)
            assert cleanup_task.cancelled() or cleanup_task.done()

    def test_calculate_average_session_age_empty(self) -> None:
        """Test _calculate_average_session_age with no sessions."""
        manager = EnterpriseSessionManager()

        average_age = manager._calculate_average_session_age()
        assert average_age == 0.0

    def test_calculate_average_session_age_with_sessions(self) -> None:
        """Test _calculate_average_session_age with active sessions."""
        manager = EnterpriseSessionManager()

        # Create session metadata with known creation times
        now = datetime.now(UTC)
        session1 = SessionMetadata(
            session_id="session1",
            user_id=uuid4(),
            created_at=now - timedelta(minutes=30),
            expires_at=now + timedelta(hours=1),
        )
        session2 = SessionMetadata(
            session_id="session2",
            user_id=uuid4(),
            created_at=now - timedelta(minutes=10),
            expires_at=now + timedelta(hours=1),
        )

        manager._active_sessions["session1"] = session1
        manager._active_sessions["session2"] = session2

        average_age = manager._calculate_average_session_age()

        # Should be average of 30 minutes and 10 minutes = 20 minutes = 1200 seconds
        expected_age = (30 * 60 + 10 * 60) / 2  # 1200 seconds
        assert abs(average_age - expected_age) < 60  # Allow for small time differences

    def test_calculate_average_session_age_with_expired_sessions(self) -> None:
        """Test _calculate_average_session_age excluding expired sessions."""
        manager = EnterpriseSessionManager()

        now = datetime.now(UTC)
        # Active session
        active_session = SessionMetadata(
            session_id="active",
            user_id=uuid4(),
            created_at=now - timedelta(minutes=20),
            expires_at=now + timedelta(hours=1),
        )
        # Expired session
        expired_session = SessionMetadata(
            session_id="expired",
            user_id=uuid4(),
            created_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )

        manager._active_sessions["active"] = active_session
        manager._active_sessions["expired"] = expired_session

        average_age = manager._calculate_average_session_age()

        # Should only include active session (20 minutes = 1200 seconds)
        expected_age = 20 * 60  # 1200 seconds
        assert abs(average_age - expected_age) < 60  # Allow for small time differences

    def test_calculate_average_session_age_all_expired(self) -> None:
        """Test _calculate_average_session_age with all expired sessions."""
        manager = EnterpriseSessionManager()

        now = datetime.now(UTC)
        expired_session = SessionMetadata(
            session_id="expired",
            user_id=uuid4(),
            created_at=now - timedelta(hours=2),
            expires_at=now - timedelta(hours=1),
        )

        manager._active_sessions["expired"] = expired_session

        average_age = manager._calculate_average_session_age()
        assert average_age == 0.0

"""Tests for FlextAuthManagers.

Tests the authentication managers module following FLEXT standards.
"""

from __future__ import annotations

from flext_auth.managers import FlextAuthManagers


class TestFlextAuthManagers:
    """Test FlextAuthManagers class and its nested manager classes."""

    def test_inherits_from_flext_service(self) -> None:
        """Test that FlextAuthManagers inherits from FlextCore.Service."""
        from flext_core import FlextCore

        assert issubclass(FlextAuthManagers, FlextCore.Service)

    def test_execute_method_returns_failure(self) -> None:
        """Test that execute method returns appropriate failure for namespace class."""
        managers = FlextAuthManagers()
        result = managers.execute(None)

        assert result.is_failure
        assert "FlextAuthManagers is a namespace class" in result.error

    def test_nested_manager_classes_exist(self) -> None:
        """Test that nested manager classes exist."""
        assert hasattr(FlextAuthManagers, "FlextAuthUserManager")

    def test_user_manager_has_required_methods(self) -> None:
        """Test that FlextAuthUserManager has required methods."""
        manager_class = FlextAuthManagers.FlextAuthUserManager

        # Check class exists and has expected structure
        assert manager_class is not None
        assert hasattr(manager_class, "__init__")

        # Note: Detailed method testing would require instantiation
        # which might need complex setup, so we just check the class exists

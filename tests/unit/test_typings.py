"""Tests for FlextAuthTypes.

Tests the authentication types module following FLEXT standards.
"""

from __future__ import annotations

from flext_auth.typings import FlextAuthTypes


class TestFlextAuthTypes:
    """Test FlextAuthTypes class and its nested type classes."""

    def test_inherits_from_flext_types(self) -> None:
        """Test that FlextAuthTypes inherits from FlextTypes."""
        from flext_core import FlextTypes

        assert issubclass(FlextAuthTypes, FlextTypes)

    def test_authentication_types_exist(self) -> None:
        """Test that authentication type classes exist."""
        assert hasattr(FlextAuthTypes, "Authentication")
        assert hasattr(FlextAuthTypes, "UserManagement")
        assert hasattr(FlextAuthTypes, "SessionManagement")
        assert hasattr(FlextAuthTypes, "TokenManagement")
        assert hasattr(FlextAuthTypes, "Authorization")
        assert hasattr(FlextAuthTypes, "Security")

    def test_typed_dict_classes_exist(self) -> None:
        """Test that TypedDict classes exist."""
        assert hasattr(FlextAuthTypes, "UserDict")
        assert hasattr(FlextAuthTypes, "SessionDict")
        assert hasattr(FlextAuthTypes, "AuthenticationResponseDict")

    def test_user_dict_structure(self) -> None:
        """Test UserDict TypedDict structure."""
        user_dict = FlextAuthTypes.UserDict

        # Check required fields
        assert "id" in user_dict.__annotations__
        assert "username" in user_dict.__annotations__
        assert "email" in user_dict.__annotations__
        assert "full_name" in user_dict.__annotations__
        assert "is_active" in user_dict.__annotations__
        assert "roles" in user_dict.__annotations__
        assert "created_at" in user_dict.__annotations__
        assert "updated_at" in user_dict.__annotations__
        assert "last_login" in user_dict.__annotations__

    def test_session_dict_structure(self) -> None:
        """Test SessionDict TypedDict structure."""
        session_dict = FlextAuthTypes.SessionDict

        # Check required fields
        assert "id" in session_dict.__annotations__
        assert "user_id" in session_dict.__annotations__
        assert "session_token" in session_dict.__annotations__
        assert "expires_at" in session_dict.__annotations__
        assert "created_at" in session_dict.__annotations__
        assert "last_accessed_at" in session_dict.__annotations__
        assert "is_active" in session_dict.__annotations__

    def test_authentication_response_dict_structure(self) -> None:
        """Test AuthenticationResponseDict TypedDict structure."""
        response_dict = FlextAuthTypes.AuthenticationResponseDict

        # Check required fields
        assert "user" in response_dict.__annotations__
        assert "session" in response_dict.__annotations__
        assert "jwt_token" in response_dict.__annotations__
        assert "authenticated" in response_dict.__annotations__
        assert "success" in response_dict.__annotations__

        # Check optional fields
        assert "tokens" in response_dict.__annotations__

    def test_project_types_exist(self) -> None:
        """Test that project type classes exist."""
        assert hasattr(FlextAuthTypes, "Project")
        assert hasattr(FlextAuthTypes.Project, "ProjectType")
        assert hasattr(FlextAuthTypes.Project, "AuthProjectConfig")

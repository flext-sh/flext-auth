"""Comprehensive tests for advanced flext-auth ABI - mixins, typedefs, decorators."""

import sys
from typing import Any

import pytest

sys.path.insert(0, "/home/marlonsc/flext/flext-auth/src")

from flext_auth import (
    # Constants
    FLEXT_AUTH_ADMIN,
    FLEXT_AUTH_GUEST,
    FLEXT_AUTH_USER,
    FlextAuthClaims,
    FlextAuthHeaders,
    # Mixins
    FlextAuthMixin,
    FlextAuthPermissions,
    FlextAuthRole,
    FlextAuthSessionData,
    FlextAuthSessionMixin,
    FlextAuthTokenData,
    # Types
    FlextAuthUserData,
    FlextAuthUserMixin,
    flext_auth_build_response,
    flext_auth_create_user_payload,
    flext_auth_extract_token_claims,
    flext_auth_filter_user_data,
    flext_auth_generate_jwt,
    # Helpers
    flext_auth_merge_configs,
    flext_auth_permission_required,
    flext_auth_rate_limit,
    # Decorators
    flext_auth_role_required,
)


class TestTypedefs:
    """Test type aliases for boilerplate reduction."""

    def test_type_aliases_are_correct_types(self) -> None:
        """Test that type aliases reference correct underlying types."""
        # These should not raise type errors in mypy
        user_data: FlextAuthUserData = {"id": "123", "username": "test"}
        session_data: FlextAuthSessionData = {"session_id": "abc", "user_id": "123"}
        token_data: FlextAuthTokenData = {"access_token": "token123"}
        headers: FlextAuthHeaders = {"Authorization": "Bearer token"}
        claims: FlextAuthClaims = {"user_id": "123", "role": "user"}
        role: FlextAuthRole = "REDACTED_LDAP_BIND_PASSWORD"
        permissions: FlextAuthPermissions = ["read", "write"]

        assert isinstance(user_data, dict)
        assert isinstance(session_data, dict)
        assert isinstance(token_data, dict)
        assert isinstance(headers, dict)
        assert isinstance(claims, dict)
        assert isinstance(role, str)
        assert isinstance(permissions, list)


class TestFlextAuthMixin:
    """Test base auth mixin functionality."""

    def test_mixin_add_validation(self) -> None:
        """Test adding custom validators."""

        class TestClass(FlextAuthMixin):
            pass

        obj = TestClass()

        # Add validators
        obj.flext_auth_add_validation(lambda x: len(x) > 5)
        obj.flext_auth_add_validation(lambda x: x.isalnum())

        # Test validation
        assert obj.flext_auth_validate_all("test123") is True
        assert obj.flext_auth_validate_all("test") is False  # Too short
        assert obj.flext_auth_validate_all("test@123") is False  # Not alphanumeric

    def test_mixin_get_headers(self) -> None:
        """Test header generation."""

        class TestClass(FlextAuthMixin):
            pass

        obj = TestClass()
        headers = obj.flext_auth_get_headers("my-token")

        expected: FlextAuthHeaders = {"Authorization": "Bearer my-token"}
        assert headers == expected


class TestFlextAuthUserMixin:
    """Test user management mixin."""

    def test_user_context_extraction(self) -> None:
        """Test extracting user context from instance."""

        class TestUser(FlextAuthUserMixin):
            def __init__(
                self,
                id: str,
                username: str,
                email: str,
                role: str = FLEXT_AUTH_USER,
            ) -> None:
                self.id = id
                self.username = username
                self.email = email
                self.role = role
                self.permissions = (
                    ["read"] if role == FLEXT_AUTH_USER else ["read", "write", "REDACTED_LDAP_BIND_PASSWORD"]
                )

        user = TestUser("123", "testuser", "test@example.com", FLEXT_AUTH_USER)
        context = user.flext_auth_get_user_context()

        expected: FlextAuthUserData = {
            "id": "123",
            "username": "testuser",
            "email": "test@example.com",
            "role": FLEXT_AUTH_USER,
            "permissions": ["read"],
        }

        assert context == expected

    def test_permission_checking(self) -> None:
        """Test permission checking logic."""

        class TestUser(FlextAuthUserMixin):
            def __init__(self, role: str, permissions: list[str]) -> None:
                self.role = role
                self.permissions = permissions

        # Admin user - has all permissions
        REDACTED_LDAP_BIND_PASSWORD = TestUser(FLEXT_AUTH_ADMIN, [])
        assert REDACTED_LDAP_BIND_PASSWORD.flext_auth_has_permission("anything") is True

        # Regular user with specific permissions
        user = TestUser(FLEXT_AUTH_USER, ["read", "write"])
        assert user.flext_auth_has_permission("read") is True
        assert user.flext_auth_has_permission("write") is True
        assert user.flext_auth_has_permission("REDACTED_LDAP_BIND_PASSWORD") is False

    def test_resource_access_control(self) -> None:
        """Test resource access control."""

        class TestUser(FlextAuthUserMixin):
            def __init__(self, role: str) -> None:
                self.role = role

        # Admin can access everything
        REDACTED_LDAP_BIND_PASSWORD = TestUser(FLEXT_AUTH_ADMIN)
        assert REDACTED_LDAP_BIND_PASSWORD.flext_auth_can_access("REDACTED_LDAP_BIND_PASSWORD/users") is True
        assert REDACTED_LDAP_BIND_PASSWORD.flext_auth_can_access("public") is True

        # User cannot access REDACTED_LDAP_BIND_PASSWORD resources
        user = TestUser(FLEXT_AUTH_USER)
        assert user.flext_auth_can_access("REDACTED_LDAP_BIND_PASSWORD/users") is False
        assert user.flext_auth_can_access("public") is True

        # Guest has limited access
        guest = TestUser(FLEXT_AUTH_GUEST)
        assert guest.flext_auth_can_access("REDACTED_LDAP_BIND_PASSWORD/users") is False
        assert guest.flext_auth_can_access("public") is True
        assert guest.flext_auth_can_access("home") is True


class TestFlextAuthSessionMixin:
    """Test session management mixin."""

    def test_session_refresh(self) -> None:
        """Test session refresh functionality."""

        class TestSession(FlextAuthSessionMixin):
            pass

        obj = TestSession()

        # First refresh creates session
        session1 = obj.flext_auth_refresh_session()
        assert "session_id" in session1
        assert "last_activity" in session1
        assert "updated_at" in session1
        assert len(session1["session_id"]) > 20

        # Second refresh updates existing session
        session2 = obj.flext_auth_refresh_session()
        assert session2["session_id"] == session1["session_id"]
        assert session2["updated_at"] != session1["updated_at"]

    def test_session_validation(self) -> None:
        """Test session validation logic."""
        from datetime import UTC, datetime, timedelta

        class TestSession(FlextAuthSessionMixin):
            def __init__(self, expires_at: str | None = None) -> None:
                if expires_at:
                    self._session = {"expires_at": expires_at}

        # No session
        obj1 = TestSession()
        assert obj1.flext_auth_is_session_valid() is False

        # Expired session
        past_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        obj2 = TestSession(past_time)
        assert obj2.flext_auth_is_session_valid() is False

        # Valid session
        future_time = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        obj3 = TestSession(future_time)
        assert obj3.flext_auth_is_session_valid() is True


class TestDictHelpers:
    """Test dictionary and configuration helpers."""

    def test_merge_configs(self) -> None:
        """Test configuration merging."""
        config1 = {
            "jwt": {"secret": "secret1", "expire": 30},
            "database": {"host": "localhost"},
        }

        config2 = {
            "jwt": {"expire": 60, "algorithm": "HS256"},
            "redis": {"host": "redis-server"},
        }

        merged = flext_auth_merge_configs(config1, config2)

        expected = {
            "jwt": {"secret": "secret1", "expire": 60, "algorithm": "HS256"},
            "database": {"host": "localhost"},
            "redis": {"host": "redis-server"},
        }

        assert merged == expected

    def test_create_user_payload(self) -> None:
        """Test user payload creation."""
        payload = flext_auth_create_user_payload(
            "user123",
            "testuser",
            role=FLEXT_AUTH_ADMIN,
            email="test@example.com",
        )

        assert payload["user_id"] == "user123"
        assert payload["username"] == "testuser"
        assert payload["role"] == FLEXT_AUTH_ADMIN
        assert payload["email"] == "test@example.com"
        assert "iat" in payload
        assert isinstance(payload["iat"], int)

    def test_extract_token_claims(self) -> None:
        """Test token claims extraction."""
        # Create a valid token first
        payload = {"user_id": "123", "username": "test", "role": FLEXT_AUTH_USER}
        token = flext_auth_generate_jwt(payload, secret="test-secret")

        # Extract claims
        claims = flext_auth_extract_token_claims(token, "test-secret")

        assert claims["user_id"] == "123"
        assert claims["username"] == "test"
        assert claims["role"] == FLEXT_AUTH_USER
        assert "iat" in claims
        assert "exp" in claims

        # Test invalid token
        empty_claims = flext_auth_extract_token_claims("invalid-token", "test-secret")
        assert empty_claims == {}

    def test_build_response(self) -> None:
        """Test standardized response building."""
        # Success response
        success_resp = flext_auth_build_response(
            True,
            data={"user": "test"},
            headers={"X-Test": "value"},
        )

        assert success_resp["success"] is True
        assert success_resp["data"] == {"user": "test"}
        assert success_resp["headers"] == {"X-Test": "value"}
        assert success_resp["status"] == 200
        assert "timestamp" in success_resp

        # Error response
        error_resp = flext_auth_build_response(
            False,
            error="Something went wrong",
            status=400,
        )

        assert error_resp["success"] is False
        assert error_resp["error"] == "Something went wrong"
        assert error_resp["status"] == 400

    def test_filter_user_data(self) -> None:
        """Test user data filtering."""
        user_data = {
            "id": "123",
            "username": "test",
            "email": "test@example.com",
            "password_hash": "secret",
            "role": FLEXT_AUTH_USER,
            "created_at": "2025-01-01",
        }

        # Filter sensitive data
        safe_data = flext_auth_filter_user_data(user_data)
        assert "password_hash" not in safe_data
        assert "username" in safe_data
        assert safe_data["id"] == "123"

        # Filter specific fields
        limited_data = flext_auth_filter_user_data(
            user_data,
            fields=["id", "username"],
            exclude_sensitive=False,
        )
        assert set(limited_data.keys()) == {"id", "username"}
        assert limited_data["id"] == "123"
        assert limited_data["username"] == "test"


class TestSpecializedDecorators:
    """Test advanced protection decorators."""

    def test_role_required_decorator(self) -> None:
        """Test role-based access control decorator."""

        @flext_auth_role_required(FLEXT_AUTH_ADMIN, "test-secret")
        def REDACTED_LDAP_BIND_PASSWORD_function(
            data: str,
            auth_context: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            return {"message": f"Admin accessed: {data}", "user": auth_context}

        # Test with REDACTED_LDAP_BIND_PASSWORD token
        REDACTED_LDAP_BIND_PASSWORD_payload = {"user_id": "123", "role": FLEXT_AUTH_ADMIN}
        REDACTED_LDAP_BIND_PASSWORD_token = flext_auth_generate_jwt(REDACTED_LDAP_BIND_PASSWORD_payload, secret="test-secret")

        result = REDACTED_LDAP_BIND_PASSWORD_function("test-data", token=REDACTED_LDAP_BIND_PASSWORD_token)
        assert result["message"] == "Admin accessed: test-data"
        assert result["user"]["role"] == FLEXT_AUTH_ADMIN

        # Test with user token (should fail)
        user_payload = {"user_id": "456", "role": FLEXT_AUTH_USER}
        user_token = flext_auth_generate_jwt(user_payload, secret="test-secret")

        result = REDACTED_LDAP_BIND_PASSWORD_function("test-data", token=user_token)
        assert result["success"] is False
        assert result["error"] == "Insufficient permissions"
        assert result["status"] == 403

    def test_permission_required_decorator(self) -> None:
        """Test permission-based access control."""

        @flext_auth_permission_required(["write", "REDACTED_LDAP_BIND_PASSWORD"], "test-secret")
        def protected_function(
            data: str,
            auth_context: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            return {"message": f"Accessed: {data}", "user": auth_context}

        # Test REDACTED_LDAP_BIND_PASSWORD (bypasses permission checks)
        REDACTED_LDAP_BIND_PASSWORD_payload = {"user_id": "123", "role": FLEXT_AUTH_ADMIN}
        REDACTED_LDAP_BIND_PASSWORD_token = flext_auth_generate_jwt(REDACTED_LDAP_BIND_PASSWORD_payload, secret="test-secret")

        result = protected_function("test-data", token=REDACTED_LDAP_BIND_PASSWORD_token)
        assert result["message"] == "Accessed: test-data"

        # Test user without required permissions
        user_payload = {
            "user_id": "456",
            "role": FLEXT_AUTH_USER,
            "permissions": ["read"],
        }
        user_token = flext_auth_generate_jwt(user_payload, secret="test-secret")

        result = protected_function("test-data", token=user_token)
        assert result["success"] is False
        assert "Missing permission:" in result["error"]

    def test_rate_limit_decorator(self) -> None:
        """Test rate limiting functionality."""

        @flext_auth_rate_limit(max_calls=2, window_minutes=60, secret_key="test-secret")
        def limited_function(
            data: str,
            auth_context: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            return {"message": f"Called with: {data}"}

        # Create user token
        user_payload = {"user_id": "123", "role": FLEXT_AUTH_USER}
        user_token = flext_auth_generate_jwt(user_payload, secret="test-secret")

        # First two calls should succeed
        result1 = limited_function("call1", token=user_token)
        assert result1["message"] == "Called with: call1"

        result2 = limited_function("call2", token=user_token)
        assert result2["message"] == "Called with: call2"

        # Third call should be rate limited
        result3 = limited_function("call3", token=user_token)
        assert result3["success"] is False
        assert result3["error"] == "Rate limit exceeded"
        assert result3["status"] == 429

    def test_decorators_without_token(self) -> None:
        """Test decorator behavior without authentication tokens."""

        @flext_auth_role_required(FLEXT_AUTH_USER)
        def protected_function() -> dict[str, Any]:
            return {"message": "success"}

        result = protected_function()
        assert result["success"] is False
        assert result["error"] == "Authentication required"
        assert result["status"] == 401


class TestIntegration:
    """Test integration between different components."""

    def test_mixin_with_helpers(self) -> None:
        """Test using mixins with helper functions."""

        class AuthenticatedUser(FlextAuthUserMixin, FlextAuthSessionMixin):
            def __init__(self, user_data: FlextAuthUserData) -> None:
                for key, value in user_data.items():
                    setattr(self, key, value)

        # Create user with helper
        user_payload = flext_auth_create_user_payload(
            "user123",
            "testuser",
            role=FLEXT_AUTH_USER,
            email="test@example.com",
        )

        user = AuthenticatedUser(user_payload)

        # Test user context
        context = user.flext_auth_get_user_context()
        assert context["user_id"] == "user123"
        assert context["username"] == "testuser"

        # Test session management
        session = user.flext_auth_refresh_session()
        assert "session_id" in session

        # Build response with user data
        filtered_data = flext_auth_filter_user_data(context)
        response = flext_auth_build_response(True, data=filtered_data)

        assert response["success"] is True
        assert response["data"]["username"] == "testuser"
        assert "password" not in response["data"]  # Sensitive data filtered

    def test_end_to_end_workflow(self) -> None:
        """Test complete workflow using all new features."""
        # 1. Create user payload
        user_data = flext_auth_create_user_payload(
            "workflow123",
            "workflowuser",
            role=FLEXT_AUTH_USER,
            email="workflow@example.com",
        )

        # 2. Generate token
        token = flext_auth_generate_jwt(user_data, secret="workflow-secret")

        # 3. Create decorator function
        @flext_auth_role_required(FLEXT_AUTH_USER, "workflow-secret")
        def workflow_endpoint(
            action: str,
            auth_context: dict[str, Any] | None = None,
        ) -> dict[str, Any]:
            filtered_user = flext_auth_filter_user_data(auth_context or {})
            return flext_auth_build_response(
                True,
                data={
                    "action": action,
                    "user": filtered_user,
                    "timestamp": auth_context.get("iat") if auth_context else None,
                },
            )

        # 4. Test the workflow
        result = workflow_endpoint("test-action", token=token)

        assert result["success"] is True
        assert result["data"]["action"] == "test-action"
        assert result["data"]["user"]["username"] == "workflowuser"
        assert result["data"]["user"]["role"] == FLEXT_AUTH_USER
        assert "timestamp" in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

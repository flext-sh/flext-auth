"""Comprehensive tests for advanced flext-auth ABI - mixins, typedefs, decorators."""

from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

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

# Constants
HTTP_OK = 200


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
        if not (obj.flext_auth_validate_all("test123")):
            raise AssertionError(
                f"Expected True, got {obj.flext_auth_validate_all('test123')}"
            )
        assert obj.flext_auth_validate_all("test") is False  # Too short
        assert obj.flext_auth_validate_all("test@123") is False  # Not alphanumeric

    def test_mixin_get_headers(self) -> None:
        """Test header generation."""

        class TestClass(FlextAuthMixin):
            pass

        obj = TestClass()
        headers = obj.flext_auth_get_headers("my-token")

        expected: FlextAuthHeaders = {"Authorization": "Bearer my-token"}
        if headers != expected:
            raise AssertionError(f"Expected {expected}, got {headers}")


class TestFlextAuthUserMixin:
    """Test user management mixin."""

    def test_user_context_extraction(self) -> None:
        """Test extracting user context from instance."""

        class TestUser(FlextAuthUserMixin):
            def __init__(
                self,
                user_id: str,
                username: str,
                email: str,
                role: str = FLEXT_AUTH_USER,
            ) -> None:
                self.id = user_id
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

        if context != expected:
            msg = f"Expected {expected}, got {context}"
            raise AssertionError(msg)

    def test_permission_checking(self) -> None:
        """Test permission checking logic."""

        class TestUser(FlextAuthUserMixin):
            def __init__(self, role: str, permissions: list[str]) -> None:
                self.role = role
                self.permissions = permissions

        # Admin user - has all permissions
        REDACTED_LDAP_BIND_PASSWORD = TestUser(FLEXT_AUTH_ADMIN, [])
        if not (REDACTED_LDAP_BIND_PASSWORD.flext_auth_has_permission("anything")):
            msg = f"Expected True, got {REDACTED_LDAP_BIND_PASSWORD.flext_auth_has_permission('anything')}"
            raise AssertionError(msg)

        # Regular user with specific permissions
        user = TestUser(FLEXT_AUTH_USER, ["read", "write"])
        if not (user.flext_auth_has_permission("read")):
            msg = f"Expected True, got {user.flext_auth_has_permission('read')}"
            raise AssertionError(msg)
        assert user.flext_auth_has_permission("write") is True
        if user.flext_auth_has_permission("REDACTED_LDAP_BIND_PASSWORD"):
            msg = f"Expected False, got {user.flext_auth_has_permission('REDACTED_LDAP_BIND_PASSWORD')}"
            raise AssertionError(msg)

    def test_resource_access_control(self) -> None:
        """Test resource access control."""

        class TestUser(FlextAuthUserMixin):
            def __init__(self, role: str) -> None:
                self.role = role

        # Admin can access everything
        REDACTED_LDAP_BIND_PASSWORD = TestUser(FLEXT_AUTH_ADMIN)
        if not (REDACTED_LDAP_BIND_PASSWORD.flext_auth_can_access("REDACTED_LDAP_BIND_PASSWORD/users")):
            msg = f"Expected True, got {REDACTED_LDAP_BIND_PASSWORD.flext_auth_can_access('REDACTED_LDAP_BIND_PASSWORD/users')}"
            raise AssertionError(msg)
        assert REDACTED_LDAP_BIND_PASSWORD.flext_auth_can_access("public") is True

        # User cannot access REDACTED_LDAP_BIND_PASSWORD resources
        user = TestUser(FLEXT_AUTH_USER)
        if user.flext_auth_can_access("REDACTED_LDAP_BIND_PASSWORD/users"):
            msg = f"Expected False, got {user.flext_auth_can_access('REDACTED_LDAP_BIND_PASSWORD/users')}"
            raise AssertionError(msg)
        if not (user.flext_auth_can_access("public")):
            msg = f"Expected True, got {user.flext_auth_can_access('public')}"
            raise AssertionError(msg)

        # Guest has limited access
        guest = TestUser(FLEXT_AUTH_GUEST)
        if guest.flext_auth_can_access("REDACTED_LDAP_BIND_PASSWORD/users"):
            msg = f"Expected False, got {guest.flext_auth_can_access('REDACTED_LDAP_BIND_PASSWORD/users')}"
            raise AssertionError(msg)
        if not (guest.flext_auth_can_access("public")):
            msg = f"Expected True, got {guest.flext_auth_can_access('public')}"
            raise AssertionError(msg)
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
        if "session_id" not in session1:
            msg = f"Expected {'session_id'} in {session1}"
            raise AssertionError(msg)
        assert "last_activity" in session1
        if "updated_at" not in session1:
            msg = f"Expected {'updated_at'} in {session1}"
            raise AssertionError(msg)
        assert len(session1["session_id"]) > 20

        # Second refresh updates existing session
        session2 = obj.flext_auth_refresh_session()
        if session2["session_id"] != session1["session_id"]:
            msg = f"Expected {session1['session_id']}, got {session2['session_id']}"
            raise AssertionError(msg)
        assert session2["updated_at"] != session1["updated_at"]

    def test_session_validation(self) -> None:
        """Test session validation logic."""

        class TestSession(FlextAuthSessionMixin):
            def __init__(self, expires_at: str | None = None) -> None:
                if expires_at:
                    self._session = {"expires_at": expires_at}

        # No session
        obj1 = TestSession()
        if obj1.flext_auth_is_session_valid():
            msg = f"Expected False, got {obj1.flext_auth_is_session_valid()}"
            raise AssertionError(msg)

        # Expired session
        past_time = (datetime.now(UTC) - timedelta(hours=1)).isoformat()
        obj2 = TestSession(past_time)
        if obj2.flext_auth_is_session_valid():
            msg = f"Expected False, got {obj2.flext_auth_is_session_valid()}"
            raise AssertionError(msg)
        # Valid session
        future_time = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
        obj3 = TestSession(future_time)
        if not (obj3.flext_auth_is_session_valid()):
            msg = f"Expected True, got {obj3.flext_auth_is_session_valid()}"
            raise AssertionError(msg)


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

        if merged != expected:
            msg = f"Expected {expected}, got {merged}"
            raise AssertionError(msg)

    def test_create_user_payload(self) -> None:
        """Test user payload creation."""
        payload = flext_auth_create_user_payload(
            "user123",
            "testuser",
            role=FLEXT_AUTH_ADMIN,
            email="test@example.com",
        )

        if payload["user_id"] != "user123":
            msg = f"Expected {'user123'}, got {payload['user_id']}"
            raise AssertionError(msg)
        assert payload["username"] == "testuser"
        if payload["role"] != FLEXT_AUTH_ADMIN:
            msg = f"Expected {FLEXT_AUTH_ADMIN}, got {payload['role']}"
            raise AssertionError(msg)
        assert payload["email"] == "test@example.com"
        if "iat" not in payload:
            msg = f"Expected {'iat'} in {payload}"
            raise AssertionError(msg)
        assert isinstance(payload["iat"], int)

    def test_extract_token_claims(self) -> None:
        """Test token claims extraction."""
        # Create a valid token first
        payload = {"user_id": "123", "username": "test", "role": FLEXT_AUTH_USER}
        token = flext_auth_generate_jwt(payload, secret="test-secret")

        # Extract claims
        claims = flext_auth_extract_token_claims(token, "test-secret")

        if claims["user_id"] != "123":
            msg = f"Expected {'123'}, got {claims['user_id']}"
            raise AssertionError(msg)
        assert claims["username"] == "test"
        if claims["role"] != FLEXT_AUTH_USER:
            msg = f"Expected {FLEXT_AUTH_USER}, got {claims['role']}"
            raise AssertionError(msg)
        if "iat" not in claims:
            msg = f"Expected {'iat'} in {claims}"
            raise AssertionError(msg)
        assert "exp" in claims

        # Test invalid token
        empty_claims = flext_auth_extract_token_claims("invalid-token", "test-secret")
        if empty_claims != {}:
            msg = f"Expected {{}}, got {empty_claims}"
            raise AssertionError(msg)

    def test_build_response(self) -> None:
        """Test standardized response building."""
        # Success response
        success_resp = flext_auth_build_response(
            success=True,
            data={"user": "test"},
            headers={"X-Test": "value"},
        )

        if not (success_resp["success"]):
            msg = f"Expected True, got {success_resp['success']}"
            raise AssertionError(msg)
        if success_resp["data"] != {"user": "test"}:
            msg = f"Expected {{'user': 'test'}}, got {success_resp['data']}"
            raise AssertionError(msg)
        assert success_resp["headers"] == {"X-Test": "value"}
        if success_resp["status"] != HTTP_OK:
            msg = f"Expected {200}, got {success_resp['status']}"
            raise AssertionError(msg)
        if "timestamp" not in success_resp:
            msg = f"Expected {'timestamp'} in {success_resp}"
            raise AssertionError(msg)

        # Error response
        error_resp = flext_auth_build_response(
            success=False,
            error="Something went wrong",
            status=400,
        )

        if error_resp["success"]:
            msg = f"Expected False, got {error_resp['success']}"
            raise AssertionError(msg)
        assert error_resp["error"] == "Something went wrong"
        if error_resp["status"] != 400:
            msg = f"Expected {400}, got {error_resp['status']}"
            raise AssertionError(msg)

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
        if "password_hash" not in safe_data:
            msg = f"Expected {'password_hash'} not in {safe_data}"
            raise AssertionError(msg)
        assert "username" in safe_data
        if safe_data["id"] != "123":
            msg = f"Expected {'123'}, got {safe_data['id']}"
            raise AssertionError(msg)

        # Filter specific fields
        limited_data = flext_auth_filter_user_data(
            user_data,
            fields=["id", "username"],
            exclude_sensitive=False,
        )
        if set(limited_data.keys()) != {"id", "username"}:
            msg = f"Expected {{'id', 'username'}}, got {set(limited_data.keys())}"
            raise AssertionError(msg)
        assert limited_data["id"] == "123"
        if limited_data["username"] != "test":
            msg = f"Expected {'test'}, got {limited_data['username']}"
            raise AssertionError(msg)


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
        if result["message"] != "Admin accessed: test-data":
            msg = f"Expected {'Admin accessed: test-data'}, got {result['message']}"
            raise AssertionError(msg)
        assert result["user"]["role"] == FLEXT_AUTH_ADMIN

        # Test with user token (should fail)
        user_payload = {"user_id": "456", "role": FLEXT_AUTH_USER}
        user_token = flext_auth_generate_jwt(user_payload, secret="test-secret")

        result = REDACTED_LDAP_BIND_PASSWORD_function("test-data", token=user_token)
        if result["success"]:
            msg = f"Expected False, got {result['success']}"
            raise AssertionError(msg)
        assert result["error"] == "Insufficient permissions"
        if result["status"] != 403:
            msg = f"Expected {403}, got {result['status']}"
            raise AssertionError(msg)

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
        if result["message"] != "Accessed: test-data":
            raise AssertionError(
                f"Expected {'Accessed: test-data'}, got {result['message']}"
            )

        # Test user without required permissions
        user_payload = {
            "user_id": "456",
            "role": FLEXT_AUTH_USER,
            "permissions": ["read"],
        }
        user_token = flext_auth_generate_jwt(user_payload, secret="test-secret")

        result = protected_function("test-data", token=user_token)
        if result["success"]:
            msg = f"Expected False, got {result['success']}"
            raise AssertionError(msg)
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
        if result1["message"] != "Called with: call1":
            raise AssertionError(
                f"Expected {'Called with: call1'}, got {result1['message']}"
            )

        result2 = limited_function("call2", token=user_token)
        if result2["message"] != "Called with: call2":
            raise AssertionError(
                f"Expected {'Called with: call2'}, got {result2['message']}"
            )

        # Third call should be rate limited
        result3 = limited_function("call3", token=user_token)
        if result3["success"]:
            msg = f"Expected False, got {result3['success']}"
            raise AssertionError(msg)
        assert result3["error"] == "Rate limit exceeded"
        if result3["status"] != 429:
            msg = f"Expected {429}, got {result3['status']}"
            raise AssertionError(msg)

    def test_decorators_without_token(self) -> None:
        """Test decorator behavior without authentication tokens."""

        @flext_auth_role_required(FLEXT_AUTH_USER)
        def protected_function() -> dict[str, Any]:
            return {"message": "success"}

        result = protected_function()
        if result["success"]:
            raise AssertionError(f"Expected False, got {result['success']}")
        assert result["error"] == "Authentication required"
        if result["status"] != 401:
            raise AssertionError(f"Expected {401}, got {result['status']}")


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
        if context["user_id"] != "user123":
            raise AssertionError(f"Expected {'user123'}, got {context['user_id']}")
        assert context["username"] == "testuser"

        # Test session management
        session = user.flext_auth_refresh_session()
        if "session_id" not in session:
            raise AssertionError(f"Expected {'session_id'} in {session}")

        # Build response with user data
        filtered_data = flext_auth_filter_user_data(context)
        response = flext_auth_build_response(success=True, data=filtered_data)

        if not (response["success"]):
            raise AssertionError(f"Expected True, got {response['success']}")
        if response["data"]["username"] != "testuser":
            raise AssertionError(
                f"Expected {'testuser'}, got {response['data']['username']}"
            )
        if "password" not in response["data"]:  # Sensitive data filtered:
            raise AssertionError(
                f"Expected {'password'} not in {response['data']}"  # Sensitive data filtered
            )

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
                success=True,
                data={
                    "action": action,
                    "user": filtered_user,
                    "timestamp": auth_context.get("iat") if auth_context else None,
                },
            )

        # 4. Test the workflow
        result = workflow_endpoint("test-action", token=token)

        if not (result["success"]):
            raise AssertionError(f"Expected True, got {result['success']}")
        if result["data"]["action"] != "test-action":
            raise AssertionError(
                f"Expected {'test-action'}, got {result['data']['action']}"
            )
        assert result["data"]["user"]["username"] == "workflowuser"
        if result["data"]["user"]["role"] != FLEXT_AUTH_USER:
            raise AssertionError(
                f"Expected {FLEXT_AUTH_USER}, got {result['data']['user']['role']}"
            )
        if "timestamp" not in result:
            raise AssertionError(f"Expected {'timestamp'} in {result}")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

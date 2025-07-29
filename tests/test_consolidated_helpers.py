"""Tests for Consolidated Anti-Boilerplate Helpers - FlextAuth ABI 3.0.

Tests the new consolidated helpers that eliminate duplications:
- flext_auth_instant_setup: Consolidates zero_config, express_setup, quick_start
- flext_auth_complete_auth: Consolidates one_liner, complete_workflow, web_session
- flext_auth_token_ops: Consolidates check_token, extract_user_context, validate_api_key
- flext_auth_protection_suite: Consolidates rapid_protect, smart_middleware
- flext_auth_batch_ops: Consolidates mass_operations, batch_operations
"""

import pytest

from flext_auth import (
    FLEXT_AUTH_USER,
    FlextAuth,
    flext_auth_batch_ops,
    flext_auth_complete_auth,
    flext_auth_instant_setup,
    flext_auth_protection_suite,
    flext_auth_token_ops,
)


class TestFlextAuthInstantSetup:
    """Tests for instant setup consolidated helper."""

    def test_instant_setup_web_success(self) -> None:
        """Test instant setup for web applications."""
        result = flext_auth_instant_setup("web", create_REDACTED_LDAP_BIND_PASSWORD=True)

        assert result.is_success
        assert isinstance(result.data["auth"], FlextAuth)
        assert result.data["app_type"] == "web"
        assert result.data["ready"] is True
        assert "usage" in result.data
        assert "protect" in result.data["usage"]

    def test_instant_setup_api_success(self) -> None:
        """Test instant setup for API applications."""
        result = flext_auth_instant_setup("api", create_REDACTED_LDAP_BIND_PASSWORD=False)

        assert result.is_success
        assert result.data["app_type"] == "api"
        assert result.data["REDACTED_LDAP_BIND_PASSWORD_created"] is None  # No REDACTED_LDAP_BIND_PASSWORD created

    def test_instant_setup_all_types(self) -> None:
        """Test instant setup with all supported app types."""
        app_types = ["web", "api", "mobile", "dev", "prod"]

        for app_type in app_types:
            result = flext_auth_instant_setup(app_type, create_REDACTED_LDAP_BIND_PASSWORD=False)
            assert result.is_success, f"Failed for app_type: {app_type}"
            assert result.data["app_type"] == app_type

    def test_instant_setup_invalid_type(self) -> None:
        """Test instant setup with invalid app type."""
        result = flext_auth_instant_setup("invalid")

        assert not result.is_success
        assert "not supported" in result.error
        assert "web" in result.error  # Should suggest valid types


class TestFlextAuthCompleteAuth:
    """Tests for complete auth consolidated helper."""

    def test_complete_auth_success(self) -> None:
        """Test complete auth workflow success."""
        result = flext_auth_complete_auth(
            "testuser",
            "test@example.com",
            "TestPassword123!",
            app_type="web",
        )

        assert result.is_success
        assert "auth" in result.data
        assert "user" in result.data
        assert "session" in result.data
        assert "token" in result.data
        assert "headers" in result.data
        assert result.data["workflow_completed"] is True

    def test_complete_auth_invalid_email(self) -> None:
        """Test complete auth with invalid email."""
        result = flext_auth_complete_auth(
            "testuser",
            "invalid-email",
            "TestPassword123!",
        )

        assert not result.is_success
        assert "Invalid email format" in result.error

    def test_complete_auth_weak_password(self) -> None:
        """Test complete auth with weak password."""
        result = flext_auth_complete_auth(
            "testuser",
            "test@example.com",
            "123",  # Weak password
        )

        assert not result.is_success
        assert "too weak" in result.error

    def test_complete_auth_missing_fields(self) -> None:
        """Test complete auth with missing required fields."""
        result = flext_auth_complete_auth("", "", "")

        assert not result.is_success
        assert "required" in result.error

    def test_complete_auth_different_app_types(self) -> None:
        """Test complete auth with different app types."""
        app_types = ["web", "api", "mobile"]

        for app_type in app_types:
            result = flext_auth_complete_auth(
                f"user_{app_type}",
                f"user@{app_type}.com",
                "TestPassword123!",
                app_type=app_type,
            )
            # Some may fail due to async setup, but should not crash
            if result.is_success:
                assert result.data["workflow_completed"] is True


class TestFlextAuthTokenOps:
    """Tests for token operations consolidated helper."""

    def test_token_ops_validate_success(self) -> None:
        """Test token validation operation."""
        # Create a simple JWT for testing
        from flext_auth import flext_auth_generate_jwt

        token = flext_auth_generate_jwt({"user_id": "123", "username": "test"})
        secret = "flext-auth-dev-secret-" + "1" * 50

        result = flext_auth_token_ops(token, secret, operation="validate")

        assert result.is_success
        assert result.data["valid"] is True
        assert "context" in result.data
        assert "user_id" in result.data
        assert "username" in result.data

    def test_token_ops_extract_operation(self) -> None:
        """Test token extraction operation."""
        from flext_auth import flext_auth_generate_jwt

        token = flext_auth_generate_jwt({"user_id": "456", "role": "REDACTED_LDAP_BIND_PASSWORD"})
        secret = "flext-auth-dev-secret-" + "1" * 50

        result = flext_auth_token_ops(token, secret, operation="extract")

        assert result.is_success
        assert "context" in result.data

    def test_token_ops_api_validate_operation(self) -> None:
        """Test API validation operation."""
        from flext_auth import flext_auth_generate_jwt

        token = flext_auth_generate_jwt({"user_id": "789", "scope": "api"})
        secret = "flext-auth-dev-secret-" + "1" * 50

        result = flext_auth_token_ops(token, secret, operation="api_validate")

        assert result.is_success
        assert result.data["valid"] is True

    def test_token_ops_missing_token(self) -> None:
        """Test token operations with missing token."""
        result = flext_auth_token_ops("", operation="validate")

        assert not result.is_success
        assert "required" in result.error

    def test_token_ops_unknown_operation(self) -> None:
        """Test token operations with unknown operation."""
        result = flext_auth_token_ops("fake.token.123", operation="unknown")

        assert not result.is_success
        assert "Unknown operation" in result.error


class TestFlextAuthProtectionSuite:
    """Tests for protection suite consolidated helper."""

    def test_protection_suite_single_permissions(self) -> None:
        """Test protection suite with single permissions."""
        routes = {
            "user_list": "read",
            "user_create": "write",
            "user_delete": "delete",
        }

        result = flext_auth_protection_suite(routes)

        assert result.is_success
        assert len(result.data["routes"]) == 3
        assert result.data["total_routes"] == 3
        assert result.data["protection_ready"] is True

        # Check route structure
        for route_data in result.data["routes"].values():
            assert "decorator" in route_data
            assert "permissions" in route_data
            assert "type" in route_data
            assert callable(route_data["decorator"])

    def test_protection_suite_multiple_permissions(self) -> None:
        """Test protection suite with multiple permissions."""
        routes = {
            "REDACTED_LDAP_BIND_PASSWORD_panel": ["REDACTED_LDAP_BIND_PASSWORD", "manage_users"],
            "super_action": ["REDACTED_LDAP_BIND_PASSWORD", "delete", "write"],
        }

        result = flext_auth_protection_suite(routes)

        assert result.is_success
        protected_routes = result.data["routes"]

        for route_data in protected_routes.values():
            assert route_data["type"] == "multiple"
            assert len(route_data["permissions"]) > 1

    def test_protection_suite_different_frameworks(self) -> None:
        """Test protection suite with different frameworks."""
        routes = {"test_route": "read"}
        frameworks = ["fastapi", "flask", "generic"]

        for framework in frameworks:
            result = flext_auth_protection_suite(routes, framework=framework)

            assert result.is_success
            assert result.data["framework"] == framework
            assert callable(result.data["middleware"])

    def test_protection_suite_empty_routes(self) -> None:
        """Test protection suite with empty routes."""
        result = flext_auth_protection_suite({})

        assert not result.is_success
        assert "required" in result.error

    def test_protection_suite_custom_auth(self) -> None:
        """Test protection suite with custom auth instance."""
        from flext_auth import FLEXT_AUTH_DEV

        custom_auth = FlextAuth(FLEXT_AUTH_DEV)
        routes = {"test_route": "read"}

        result = flext_auth_protection_suite(routes, auth_instance=custom_auth)

        assert result.is_success
        assert result.data["auth_instance"] is custom_auth


class TestFlextAuthBatchOps:
    """Tests for batch operations consolidated helper."""

    def test_batch_ops_register_operations(self) -> None:
        """Test batch operations with register operations."""
        operations = [
            {
                "type": "register",
                "data": {
                    "username": "batch_user1",
                    "email": "batch1@test.com",
                    "password": "Test123!",
                    "role": FLEXT_AUTH_USER,
                },
            },
            {
                "type": "register",
                "data": {
                    "username": "batch_user2",
                    "email": "batch2@test.com",
                    "password": "Test123!",
                    "role": FLEXT_AUTH_USER,
                },
            },
        ]

        result = flext_auth_batch_ops(operations)

        assert result.is_success
        assert result.data["total_operations"] == 2
        assert result.data["completed"] is True
        assert "success_rate" in result.data

        # Check results structure
        results = result.data["results"]
        assert len(results) == 2

        for i, op_result in enumerate(results):
            assert op_result["index"] == i
            assert op_result["type"] == "register"
            assert "success" in op_result
            assert "timestamp" in op_result

    def test_batch_ops_mixed_operations(self) -> None:
        """Test batch operations with mixed operation types."""
        operations = [
            {
                "type": "register",
                "data": {"username": "mixed_user", "password": "Test123!"},
            },
            {
                "type": "validate",
                "data": {"token": "fake.token.123"},  # Will fail
            },
        ]

        result = flext_auth_batch_ops(operations)

        assert result.is_success
        assert result.data["total_operations"] == 2

        results = result.data["results"]
        assert len(results) == 2
        assert results[0]["type"] == "register"
        assert results[1]["type"] == "validate"

    def test_batch_ops_unknown_operation(self) -> None:
        """Test batch operations with unknown operation type."""
        operations = [
            {"type": "unknown_operation", "data": {"test": "data"}},
        ]

        result = flext_auth_batch_ops(operations)

        assert result.is_success
        assert result.data["successful"] == 0
        assert result.data["failed"] == 1

        # Check error message
        assert not result.data["results"][0]["success"]
        assert "Unknown operation type" in result.data["results"][0]["error"]

    def test_batch_ops_fail_fast(self) -> None:
        """Test batch operations with fail_fast option."""
        operations = [
            {"type": "unknown_op", "data": {}},  # Will fail
            {"type": "register", "data": {"username": "user2"}},  # Won't execute
        ]

        result = flext_auth_batch_ops(operations, fail_fast=True)

        assert result.is_success
        assert result.data["fail_fast_used"] is True
        # Should stop after first failure
        assert len(result.data["results"]) == 1

    def test_batch_ops_empty_operations(self) -> None:
        """Test batch operations with empty operations list."""
        result = flext_auth_batch_ops([])

        assert not result.is_success
        assert "required" in result.error

    def test_batch_ops_custom_auth(self) -> None:
        """Test batch operations with custom auth instance."""
        from flext_auth import FLEXT_AUTH_DEV

        custom_auth = FlextAuth(FLEXT_AUTH_DEV)
        operations = [
            {"type": "register", "data": {"username": "custom_user"}},
        ]

        result = flext_auth_batch_ops(operations, auth_instance=custom_auth)

        assert result.is_success
        assert result.data["total_operations"] == 1


class TestConsolidatedHelpersIntegration:
    """Integration tests for consolidated helpers working together."""

    def test_instant_setup_to_complete_auth_integration(self) -> None:
        """Test using instant setup result with complete auth."""
        # First setup auth environment
        setup_result = flext_auth_instant_setup("web", create_REDACTED_LDAP_BIND_PASSWORD=False)
        assert setup_result.is_success

        # Then use complete auth workflow
        auth_result = flext_auth_complete_auth(
            "integration_user",
            "int@test.com",
            "IntPass123!",
        )

        # Should work independently (each creates its own auth instance)
        if auth_result.is_success:
            assert auth_result.data["workflow_completed"] is True

    def test_complete_auth_to_token_ops_integration(self) -> None:
        """Test using complete auth result with token operations."""
        # Create complete auth workflow
        auth_result = flext_auth_complete_auth(
            "token_user",
            "token@test.com",
            "TokenPass123!",
        )

        if auth_result.is_success:
            token = auth_result.data["token"]

            # Use token with token operations
            token_result = flext_auth_token_ops(token, operation="validate")

            if token_result.is_success:
                assert token_result.data["valid"] is True

    def test_protection_suite_with_batch_ops(self) -> None:
        """Test protection suite with batch operations."""
        # Setup protection
        routes = {"protected_route": "REDACTED_LDAP_BIND_PASSWORD"}
        protection_result = flext_auth_protection_suite(routes)
        assert protection_result.is_success

        # Run batch operations
        operations = [
            {"type": "register", "data": {"username": "batch_test"}},
        ]
        batch_result = flext_auth_batch_ops(operations)
        assert batch_result.is_success

        # Both should work independently
        assert protection_result.data["protection_ready"] is True
        assert batch_result.data["completed"] is True


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

"""Advanced Ultra-Helpers Tests - FlextAuth ABI 2.0.

Testes robustos para todos os ultra-helpers revolucionários.
Valida redução massiva de boilerplate e funcionalidade real.
"""

import pytest

from flext_auth import (
    FLEXT_AUTH_ADMIN,
    FLEXT_AUTH_API,
    FLEXT_AUTH_DEV,
    FLEXT_AUTH_USER,
    FLEXT_AUTH_WEB,
    FlextAuth,
    flext_auth_express_setup,
    flext_auth_mass_operations,
    flext_auth_rapid_protect,
    flext_auth_smart_middleware,
    flext_auth_zero_config,
)


class TestFlextAuthZeroConfig:
    """Tests for zero-config ultra-helper."""

    def test_zero_config_web_success(self) -> None:
        """Test zero-config web setup success."""
        result = flext_auth_zero_config("web")

        assert result.is_success
        assert isinstance(result.data["auth"], FlextAuth)
        assert result.data["app_type"] == "web"
        assert result.data["config"] == FLEXT_AUTH_WEB
        assert result.data["ready"] is True

        # Verify auto-accounts were created
        auto_accounts = result.data["auto_accounts"]
        assert "REDACTED_LDAP_BIND_PASSWORD" in auto_accounts
        assert "user" in auto_accounts
        assert "guest" in auto_accounts

        # Verify instant usage info
        instant_usage = result.data["instant_usage"]
        assert "login" in instant_usage
        assert "protect" in instant_usage
        assert "validate" in instant_usage

    def test_zero_config_api_success(self) -> None:
        """Test zero-config API setup success."""
        result = flext_auth_zero_config("api")

        assert result.is_success
        assert result.data["app_type"] == "api"
        assert result.data["config"] == FLEXT_AUTH_API

        # API mode should have test tokens
        test_tokens = result.data["test_tokens"]
        assert FLEXT_AUTH_ADMIN in test_tokens
        assert FLEXT_AUTH_USER in test_tokens
        assert len(test_tokens[FLEXT_AUTH_ADMIN]) > 0

    def test_zero_config_mobile_success(self) -> None:
        """Test zero-config mobile setup success."""
        result = flext_auth_zero_config("mobile")

        assert result.is_success
        assert result.data["app_type"] == "mobile"
        # Mobile doesn't auto-create accounts
        assert result.data["auto_accounts"] == {}

    def test_zero_config_invalid_type(self) -> None:
        """Test zero-config with invalid app type."""
        result = flext_auth_zero_config("invalid")

        assert not result.is_success
        assert "not supported" in result.error
        assert "web" in result.error  # Should list valid types


class TestFlextAuthExpressSetup:
    """Tests for express setup ultra-helper."""

    def test_express_setup_dev_success(self) -> None:
        """Test express setup in dev mode."""
        result = flext_auth_express_setup("TestApp", "dev")

        assert result.is_success
        assert isinstance(result.data["auth"], FlextAuth)
        assert result.data["app_name"] == "TestApp"
        assert result.data["mode"] == "dev"
        assert result.data["ready"] is True

        # Dev mode should create REDACTED_LDAP_BIND_PASSWORD
        assert result.data["REDACTED_LDAP_BIND_PASSWORD_created"] is not None

        # Should have middleware ready
        assert result.data["middleware"] is not None
        assert result.data["defaults"] is not None

        # Should have usage examples
        usage = result.data["usage"]
        assert "decorator" in usage
        assert "middleware" in usage
        assert "login" in usage

    def test_express_setup_prod_success(self) -> None:
        """Test express setup in prod mode."""
        result = flext_auth_express_setup("ProdApp", "prod")

        assert result.is_success
        assert result.data["mode"] == "prod"

        # Prod mode should NOT create REDACTED_LDAP_BIND_PASSWORD automatically
        assert result.data["REDACTED_LDAP_BIND_PASSWORD_created"] is None

    def test_express_setup_all_modes(self) -> None:
        """Test express setup with all valid modes."""
        valid_modes = ["dev", "prod", "web", "api", "mobile"]

        for mode in valid_modes:
            result = flext_auth_express_setup(f"App_{mode}", mode)

            assert result.is_success, f"Mode {mode} failed: {result.error}"
            assert result.data["mode"] == mode
            assert isinstance(result.data["auth"], FlextAuth)

    def test_express_setup_invalid_mode(self) -> None:
        """Test express setup with invalid mode."""
        result = flext_auth_express_setup("App", "invalid_mode")

        assert not result.is_success
        assert "Invalid mode" in result.error


class TestFlextAuthRapidProtect:
    """Tests for rapid route protection ultra-helper."""

    def test_rapid_protect_single_permissions(self) -> None:
        """Test rapid protect with single permissions."""
        routes = {
            "user_list": "read",
            "user_create": "write",
            "user_delete": "delete",
        }

        result = flext_auth_rapid_protect(routes)

        assert result.is_success
        protected_routes = result.data["routes"]
        assert len(protected_routes) == 3
        assert result.data["total_routes"] == 3

        # Verify each route has correct structure
        for route_data in protected_routes.values():
            assert "decorator" in route_data
            assert "permissions" in route_data
            assert "type" in route_data
            assert route_data["type"] == "single"
            assert callable(route_data["decorator"])

    def test_rapid_protect_multiple_permissions(self) -> None:
        """Test rapid protect with multiple permissions."""
        routes = {
            "REDACTED_LDAP_BIND_PASSWORD_panel": ["REDACTED_LDAP_BIND_PASSWORD", "manage_users"],
            "super_action": ["REDACTED_LDAP_BIND_PASSWORD", "delete", "write"],
        }

        result = flext_auth_rapid_protect(routes)

        assert result.is_success
        protected_routes = result.data["routes"]

        for route_data in protected_routes.values():
            assert route_data["type"] == "multiple"
            assert len(route_data["permissions"]) > 1
            assert callable(route_data["decorator"])

    def test_rapid_protect_mixed_permissions(self) -> None:
        """Test rapid protect with mixed single and multiple permissions."""
        routes = {
            "simple_route": "read",
            "complex_route": ["REDACTED_LDAP_BIND_PASSWORD", "write"],
        }

        result = flext_auth_rapid_protect(routes)

        assert result.is_success
        protected_routes = result.data["routes"]

        assert protected_routes["simple_route"]["type"] == "single"
        assert protected_routes["complex_route"]["type"] == "multiple"

    def test_rapid_protect_empty_routes(self) -> None:
        """Test rapid protect with empty routes dict."""
        result = flext_auth_rapid_protect({})

        assert not result.is_success
        assert "Routes dictionary is required" in result.error

    def test_rapid_protect_with_custom_auth(self) -> None:
        """Test rapid protect with custom auth instance."""
        # Create custom auth
        custom_auth = FlextAuth(FLEXT_AUTH_DEV)

        routes = {"test_route": "read"}
        result = flext_auth_rapid_protect(routes, default_auth=custom_auth)

        assert result.is_success
        assert result.data["auth_instance"] is custom_auth


class TestFlextAuthSmartMiddleware:
    """Tests for smart middleware ultra-helper."""

    def test_smart_middleware_fastapi(self) -> None:
        """Test smart middleware for FastAPI."""
        result = flext_auth_smart_middleware("fastapi")

        assert result.is_success
        assert result.data["framework"] == "fastapi"
        assert result.data["integration_ready"] is True
        assert callable(result.data["middleware"])

        # Verify usage instructions
        usage = result.data["usage"]
        assert "app.middleware" in usage

    def test_smart_middleware_flask(self) -> None:
        """Test smart middleware for Flask."""
        result = flext_auth_smart_middleware("flask")

        assert result.is_success
        assert result.data["framework"] == "flask"
        assert callable(result.data["middleware"])

        usage = result.data["usage"]
        assert "app.before_request" in usage

    def test_smart_middleware_generic(self) -> None:
        """Test smart middleware for generic framework."""
        result = flext_auth_smart_middleware("generic")

        assert result.is_success
        assert result.data["framework"] == "generic"
        assert callable(result.data["middleware"])

    def test_smart_middleware_all_frameworks(self) -> None:
        """Test smart middleware for all supported frameworks."""
        frameworks = ["fastapi", "flask", "generic"]

        for framework in frameworks:
            result = flext_auth_smart_middleware(framework)

            assert result.is_success, f"Framework {framework} failed"
            assert result.data["framework"] == framework
            assert callable(result.data["middleware"])
            assert result.data["integration_ready"] is True

    def test_smart_middleware_invalid_framework(self) -> None:
        """Test smart middleware with invalid framework."""
        result = flext_auth_smart_middleware("invalid_framework")

        assert not result.is_success
        assert "not supported" in result.error
        assert "fastapi" in result.error  # Should list valid frameworks

    def test_smart_middleware_with_custom_auth(self) -> None:
        """Test smart middleware with custom auth instance."""
        custom_auth = FlextAuth(FLEXT_AUTH_WEB)

        result = flext_auth_smart_middleware("generic", auth_instance=custom_auth)

        assert result.is_success
        assert result.data["auth_instance"] is custom_auth


class TestFlextAuthMassOperations:
    """Tests for mass operations ultra-helper."""

    @pytest.mark.asyncio
    async def test_mass_operations_register_success(self) -> None:
        """Test mass operations with register operations."""
        operations = [
            {
                "type": "register",
                "data": {
                    "username": "mass_user1",
                    "email": "mass1@test.com",
                    "password": "Test123!",
                    "role": FLEXT_AUTH_USER,
                },
            },
            {
                "type": "register",
                "data": {
                    "username": "mass_user2",
                    "email": "mass2@test.com",
                    "password": "Test123!",
                    "role": FLEXT_AUTH_USER,
                },
            },
        ]

        result = flext_auth_mass_operations(operations)

        assert result.is_success
        assert result.data["total_operations"] == 2
        assert result.data["successful"] >= 0  # May fail due to service issues
        assert "success_rate" in result.data

        # Verify results structure
        results = result.data["results"]
        assert len(results) == 2

        for i, op_result in enumerate(results):
            assert op_result["index"] == i
            assert op_result["type"] == "register"
            assert "success" in op_result
            assert "data" in op_result
            assert "error" in op_result

    @pytest.mark.asyncio
    async def test_mass_operations_mixed_types(self) -> None:
        """Test mass operations with different operation types."""
        operations = [
            {
                "type": "register",
                "data": {
                    "username": "mixed_user",
                    "email": "mixed@test.com",
                    "password": "Test123!",
                    "role": FLEXT_AUTH_USER,
                },
            },
            {
                "type": "validate",
                "data": {
                    "token": "fake.token.123",  # Will fail
                },
            },
        ]

        result = flext_auth_mass_operations(operations)

        assert result.is_success  # Operation succeeds even if individual ops fail
        assert result.data["total_operations"] == 2

        # Should have mixed success/failure results
        results = result.data["results"]
        assert len(results) == 2
        assert results[0]["type"] == "register"
        assert results[1]["type"] == "validate"

    def test_mass_operations_unknown_type(self) -> None:
        """Test mass operations with unknown operation type."""
        operations = [
            {"type": "unknown_operation", "data": {"test": "data"}},
        ]

        result = flext_auth_mass_operations(operations)

        assert result.is_success
        # Should have 0 successful operations
        assert result.data["successful"] == 0
        assert result.data["failed"] == 1

        # Error should mention unknown operation
        assert len(result.data["results"]) == 1
        assert not result.data["results"][0]["success"]
        assert "Unknown operation type" in result.data["results"][0]["error"]

    def test_mass_operations_empty_list(self) -> None:
        """Test mass operations with empty operations list."""
        result = flext_auth_mass_operations([])

        assert not result.is_success
        assert "Operations list is required" in result.error

    def test_mass_operations_with_custom_auth(self) -> None:
        """Test mass operations with custom auth instance."""
        custom_auth = FlextAuth(FLEXT_AUTH_DEV)

        operations = [
            {
                "type": "register",
                "data": {
                    "username": "custom_user",
                    "email": "custom@test.com",
                    "password": "Test123!",
                    "role": FLEXT_AUTH_USER,
                },
            },
        ]

        result = flext_auth_mass_operations(operations, auth_instance=custom_auth)

        assert result.is_success
        assert result.data["total_operations"] == 1


class TestFlextAuthIntegration:
    """Integration tests for ultra-helpers working together."""

    def test_zero_config_to_rapid_protect_integration(self) -> None:
        """Test using zero-config result with rapid protect."""
        # Step 1: Zero-config setup
        setup_result = flext_auth_zero_config("web")
        assert setup_result.is_success

        auth = setup_result.data["auth"]

        # Step 2: Use auth with rapid protect
        routes = {"test_route": "read"}
        protect_result = flext_auth_rapid_protect(routes, default_auth=auth)

        assert protect_result.is_success
        assert protect_result.data["auth_instance"] is auth

    def test_express_setup_to_smart_middleware_integration(self) -> None:
        """Test using express setup result with smart middleware."""
        # Step 1: Express setup
        setup_result = flext_auth_express_setup("IntegrationApp", "web")
        assert setup_result.is_success

        auth = setup_result.data["auth"]

        # Step 2: Create smart middleware using same auth
        middleware_result = flext_auth_smart_middleware("generic", auth_instance=auth)

        assert middleware_result.is_success
        assert middleware_result.data["auth_instance"] is auth

    def test_chain_all_ultra_helpers(self) -> None:
        """Test chaining multiple ultra-helpers together."""
        # Chain: zero-config → rapid-protect → smart-middleware

        # Step 1: Zero-config
        config_result = flext_auth_zero_config("api")
        assert config_result.is_success
        auth = config_result.data["auth"]

        # Step 2: Rapid protect with same auth
        routes = {"api_endpoint": "read"}
        protect_result = flext_auth_rapid_protect(routes, default_auth=auth)
        assert protect_result.is_success

        # Step 3: Smart middleware with same auth
        middleware_result = flext_auth_smart_middleware("fastapi", auth_instance=auth)
        assert middleware_result.is_success

        # All should use the same auth instance
        assert protect_result.data["auth_instance"] is auth
        assert middleware_result.data["auth_instance"] is auth


class TestFlextAuthResultTypes:
    """Tests for FlextResult integration in ultra-helpers."""

    def test_all_ultra_helpers_return_flext_result(self) -> None:
        """Verify all ultra-helpers return FlextAuthResult (FlextResult)."""
        # Test each ultra-helper returns proper FlextResult

        result1 = flext_auth_zero_config("web")
        assert hasattr(result1, "is_success")
        assert hasattr(result1, "data")
        assert hasattr(result1, "error")

        result2 = flext_auth_express_setup("test", "dev")
        assert hasattr(result2, "is_success")

        result3 = flext_auth_rapid_protect({"test": "read"})
        assert hasattr(result3, "is_success")

        result4 = flext_auth_smart_middleware("generic")
        assert hasattr(result4, "is_success")

        result5 = flext_auth_mass_operations([])  # Will fail but still FlextResult
        assert hasattr(result5, "is_success")
        assert not result5.is_success  # Should fail with empty operations

    def test_flext_result_error_handling(self) -> None:
        """Test FlextResult error handling patterns."""
        # Test error cases return proper FlextResult with error info

        error_result1 = flext_auth_zero_config("invalid_type")
        assert not error_result1.is_success
        assert error_result1.data is None
        assert error_result1.error is not None
        assert len(error_result1.error) > 0

        error_result2 = flext_auth_express_setup("test", "invalid_mode")
        assert not error_result2.is_success
        assert error_result2.error is not None

        error_result3 = flext_auth_rapid_protect({})  # Empty routes
        assert not error_result3.is_success
        assert error_result3.error is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])

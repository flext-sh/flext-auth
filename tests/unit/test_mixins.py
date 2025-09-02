"""Unit tests for FlextAuth mixins module - Integration mixins.

Tests cover FlextAuthMixin class for integrating authentication
capabilities into existing classes via composition.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth.domain_services import FlextAuth
from flext_auth.mixins import FlextAuthMixin


class TestFlextAuthMixin:
    """Unit tests for FlextAuthMixin class."""

    def test_mixin_initialization(self) -> None:
        """Test FlextAuthMixin initialization."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()

        # Should initialize without auth service
        assert not test_obj.is_auth_initialized()
        assert test_obj.get_auth_service() is None
        assert test_obj._auth_service is None

    def test_mixin_multiple_inheritance_compatibility(self) -> None:
        """Test mixin works with multiple inheritance."""

        class BaseClass:
            def __init__(self, value: str) -> None:
                self.value = value
                super().__init__()

        class TestClass(BaseClass, FlextAuthMixin):
            def __init__(self, value: str) -> None:
                super().__init__(value)

        test_obj = TestClass("test_value")

        # Should have both base class and mixin functionality
        assert test_obj.value == "test_value"
        assert not test_obj.is_auth_initialized()
        assert test_obj.get_auth_service() is None

    def test_mixin_with_args_kwargs(self) -> None:
        """Test mixin handles *args and **kwargs correctly."""

        class BaseClass:
            def __init__(self, *args: object, **kwargs: object) -> None:
                self.args = args
                self.kwargs = kwargs
                super().__init__()

        class TestClass(BaseClass, FlextAuthMixin):
            def __init__(self, *args: object, **kwargs: object) -> None:
                super().__init__(*args, **kwargs)

        test_obj = TestClass("arg1", "arg2", key1="value1", key2="value2")

        # Should pass through args and kwargs
        assert test_obj.args == ("arg1", "arg2")
        assert test_obj.kwargs == {"key1": "value1", "key2": "value2"}

        # Should have mixin functionality
        assert not test_obj.is_auth_initialized()

    def test_init_auth_success(self) -> None:
        """Test successful authentication service initialization."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()
        auth_service = FlextAuth()

        # Initialize auth service
        result = test_obj.init_auth(auth_service)

        assert result.success
        assert test_obj.is_auth_initialized()
        assert test_obj.get_auth_service() is auth_service
        assert test_obj._auth_service is auth_service

    def test_init_auth_with_none(self) -> None:
        """Test auth initialization with None (should work)."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()

        # Initialize with None
        result = test_obj.init_auth(None)

        assert result.success
        assert test_obj.is_auth_initialized()  # None is still "initialized"
        assert test_obj.get_auth_service() is None

    def test_auth_service_replacement(self) -> None:
        """Test replacing authentication service."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()

        # Initialize with first service
        auth_service1 = FlextAuth()
        result1 = test_obj.init_auth(auth_service1)
        assert result1.success
        assert test_obj.get_auth_service() is auth_service1

        # Replace with second service
        auth_service2 = FlextAuth()
        result2 = test_obj.init_auth(auth_service2)
        assert result2.success
        assert test_obj.get_auth_service() is auth_service2
        assert test_obj.get_auth_service() is not auth_service1

    def test_is_auth_initialized_states(self) -> None:
        """Test is_auth_initialized in different states."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()

        # Initially not initialized
        assert not test_obj.is_auth_initialized()

        # After setting to None, still considered initialized
        test_obj._auth_service = None
        assert not test_obj.is_auth_initialized()  # None means not initialized

        # After setting to actual service
        auth_service = FlextAuth()
        test_obj._auth_service = auth_service
        assert test_obj.is_auth_initialized()

    def test_get_auth_service_states(self) -> None:
        """Test get_auth_service in different states."""

        class TestClass(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()

        # Initially None
        assert test_obj.get_auth_service() is None

        # After initialization
        auth_service = FlextAuth()
        test_obj.init_auth(auth_service)
        assert test_obj.get_auth_service() is auth_service


class TestFlextAuthMixinUsagePatterns:
    """Unit tests for common mixin usage patterns."""

    def test_mixin_in_service_class(self) -> None:
        """Test mixin usage in a service class."""

        class UserService(FlextAuthMixin):
            def __init__(self, db_connection: str) -> None:
                super().__init__()
                self.db_connection = db_connection

            def create_user(self, username: str, password: str) -> bool:
                if not self.is_auth_initialized():
                    msg = "Authentication service not initialized"
                    raise ValueError(msg)

                auth = self.get_auth_service()
                if auth is None:
                    return False

                # Use auth service to create user
                result = auth.register_user(
                    username, f"{username}@example.com", password
                )
                return result.success

            def authenticate_user(self, username: str, password: str) -> bool:
                if not self.is_auth_initialized():
                    return False

                auth = self.get_auth_service()
                if auth is None:
                    return False

                result = auth.authenticate_user(username, password)
                return result.success

        # Create service
        service = UserService("db://localhost")
        assert service.db_connection == "db://localhost"

        # Should fail without auth initialization
        with pytest.raises(ValueError):
            service.create_user("test", "password123")

        # Initialize auth
        auth = FlextAuth()
        init_result = service.init_auth(auth)
        assert init_result.success

        # Should now work
        create_result = service.create_user("testuser", "TestPassword123!")
        assert create_result is True

        # Authentication should also work
        auth_result = service.authenticate_user("testuser", "TestPassword123!")
        assert auth_result is True

    def test_mixin_in_controller_class(self) -> None:
        """Test mixin usage in a controller class."""

        class AuthController(FlextAuthMixin):
            def __init__(self, api_version: str) -> None:
                super().__init__()
                self.api_version = api_version

            def login(self, username: str, password: str) -> dict[str, object]:
                if not self.is_auth_initialized():
                    return {"error": "Auth service not available"}

                auth = self.get_auth_service()
                if auth is None:
                    return {"error": "Auth service not configured"}

                result = auth.authenticate_user(username, password)
                if result.success:
                    return {"success": True, "data": result.value}
                return {"error": result.error}

            def register(
                self, username: str, email: str, password: str
            ) -> dict[str, object]:
                if not self.is_auth_initialized():
                    return {"error": "Auth service not available"}

                auth = self.get_auth_service()
                if auth is None:
                    return {"error": "Auth service not configured"}

                result = auth.register_user(username, email, password)
                if result.success:
                    return {"success": True, "data": result.value}
                return {"error": result.error}

        # Create controller
        controller = AuthController("v1")
        assert controller.api_version == "v1"

        # Should return error without auth
        login_result = controller.login("test", "password")
        assert "error" in login_result
        assert login_result["error"] == "Auth service not available"

        # Initialize auth
        auth = FlextAuth()
        controller.init_auth(auth)

        # Register user
        register_result = controller.register(
            "testuser", "test@example.com", "TestPassword123!"
        )
        assert register_result.get("success") is True

        # Login user
        login_result = controller.login("testuser", "TestPassword123!")
        assert login_result.get("success") is True

    def test_mixin_with_dependency_injection(self) -> None:
        """Test mixin usage with dependency injection pattern."""

        class AuthenticatedService(FlextAuthMixin):
            def __init__(self, config: dict[str, str]) -> None:
                super().__init__()
                self.config = config

            def get_current_user(self, token: str) -> dict[str, str] | None:
                if not self.is_auth_initialized():
                    return None

                auth = self.get_auth_service()
                if auth is None:
                    return None

                validation_result = auth.validate_token(token)
                if validation_result.success:
                    return {
                        "user_id": validation_result.value.get("user_id", ""),
                        "username": validation_result.value.get("username", ""),
                        "role": validation_result.value.get("role", ""),
                    }
                return None

        # Dependency injection setup
        config = {"env": "test", "debug": "true"}
        auth_service = FlextAuth()

        service = AuthenticatedService(config)
        service.init_auth(auth_service)

        # Create a user and get token for testing
        auth_service.register_user("testuser", "test@example.com", "TestPassword123!")
        auth_result = auth_service.authenticate_user("testuser", "TestPassword123!")
        assert auth_result.success

        token = auth_result.value["tokens"]["access_token"]

        # Test getting current user
        current_user = service.get_current_user(token)
        assert current_user is not None
        assert current_user["username"] == "testuser"


class TestFlextAuthMixinEdgeCases:
    """Unit tests for mixin edge cases and error conditions."""

    def test_mixin_without_super_init(self) -> None:
        """Test behavior when super().__init__() is not called."""

        class BadTestClass(FlextAuthMixin):
            def __init__(self) -> None:
                # Forgot to call super().__init__()
                pass

        # Should still work due to mixin's __init__ handling
        BadTestClass()

        # Mixin attributes might not be initialized
        # This depends on Python's MRO and when mixin __init__ gets called
        # The mixin should be defensive about this

    def test_mixin_with_complex_inheritance(self) -> None:
        """Test mixin in complex inheritance hierarchy."""

        class BaseService:
            def __init__(self, name: str) -> None:
                self.name = name
                super().__init__()

        class CacheService(BaseService):
            def __init__(self, name: str, cache_size: int) -> None:
                self.cache_size = cache_size
                super().__init__(name)

        class AuthenticatedCacheService(CacheService, FlextAuthMixin):
            def __init__(self, name: str, cache_size: int) -> None:
                super().__init__(name, cache_size)

        service = AuthenticatedCacheService("test-service", 1000)

        # Should have all properties from inheritance chain
        assert service.name == "test-service"
        assert service.cache_size == 1000
        assert not service.is_auth_initialized()

        # Should be able to initialize auth
        auth = FlextAuth()
        result = service.init_auth(auth)
        assert result.success
        assert service.is_auth_initialized()

    def test_mixin_method_override(self) -> None:
        """Test overriding mixin methods."""

        class CustomFlextAuthMixin(FlextAuthMixin):
            def is_auth_initialized(self) -> bool:
                # Custom logic - maybe more strict checking
                auth = self.get_auth_service()
                return auth is not None and hasattr(auth, "jwt_secret")

        class TestClass(CustomFlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()

        test_obj = TestClass()

        # Should use overridden method
        assert not test_obj.is_auth_initialized()

        # Initialize with auth service
        auth = FlextAuth()
        test_obj.init_auth(auth)

        # Should now pass custom check
        assert test_obj.is_auth_initialized()

    def test_mixin_type_annotations(self) -> None:
        """Test mixin works correctly with type annotations."""

        class TypedService(FlextAuthMixin):
            def __init__(self, config: dict[str, str]) -> None:
                super().__init__()
                self.config: dict[str, str] = config

            def process_with_auth(self, data: str) -> str | None:
                auth: FlextAuth | None = self.get_auth_service()
                if auth is None:
                    return None

                # Type checker should understand auth is FlextAuth here
                return f"Processed {data} with auth"

        service = TypedService({"key": "value"})
        auth = FlextAuth()
        service.init_auth(auth)

        result = service.process_with_auth("test_data")
        assert result == "Processed test_data with auth"


class TestFlextAuthMixinIntegration:
    """Integration tests for FlextAuthMixin with real auth operations."""

    def test_complete_auth_workflow_with_mixin(self) -> None:
        """Test complete authentication workflow using mixin."""

        class UserManager(FlextAuthMixin):
            def __init__(self) -> None:
                super().__init__()
                self.users: list[str] = []

            def create_and_authenticate_user(
                self, username: str, email: str, password: str
            ) -> dict[str, object]:
                if not self.is_auth_initialized():
                    return {"error": "Auth not initialized"}

                auth = self.get_auth_service()
                if auth is None:
                    return {"error": "Auth service unavailable"}

                # Register user
                reg_result = auth.register_user(username, email, password)
                if not reg_result.success:
                    return {"error": f"Registration failed: {reg_result.error}"}

                # Authenticate user
                auth_result = auth.authenticate_user(username, password)
                if not auth_result.success:
                    return {"error": f"Authentication failed: {auth_result.error}"}

                # Add to local user list
                self.users.append(username)

                return {
                    "success": True,
                    "user": auth_result.value["user"],
                    "token": auth_result.value["tokens"]["access_token"],
                }

        # Setup
        manager = UserManager()
        auth = FlextAuth()
        manager.init_auth(auth)

        # Test complete workflow
        result = manager.create_and_authenticate_user(
            "testuser", "test@example.com", "TestPassword123!"
        )

        assert result.get("success") is True
        assert "user" in result
        assert "token" in result
        assert "testuser" in manager.users

        # Verify token works
        token = result["token"]
        validation_result = auth.validate_token(str(token))
        assert validation_result.success
        assert validation_result.value["username"] == "testuser"

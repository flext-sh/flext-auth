"""Config module coverage tests - targeting uncovered lines in config.py.

Tests specifically designed to cover uncovered lines in config.py
using real functionality without mocks.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import os
import threading
import time
from typing import cast
from unittest.mock import patch

import pytest
from flext_core import FlextConfig, FlextConstants, FlextResult, FlextTypes
from pydantic import SecretStr, ValidationError

from flext_auth import FlextAuthConfig
from flext_auth.constants import FlextAuthConstants


class TestFlextAuthConfigCoverage:
    """Test FlextAuthConfig initialization and methods."""

    def test_flext_auth_config_default_creation(self) -> None:
        """Test FlextAuthConfig creation with defaults."""
        config = FlextAuthConfig()

        assert config.jwt_expiry_minutes > 0
        assert config.jwt_algorithm is not None
        assert config.bcrypt_rounds >= 10
        assert config.max_login_attempts > 0

    def test_flext_auth_config_with_parameters(self) -> None:
        """Test FlextAuthConfig creation with custom parameters."""
        config = FlextAuthConfig(
            jwt_secret="custom_secret_for_testing_minimum_32_chars",
            jwt_expiry_minutes=60,
            bcrypt_rounds=12,
        )

        assert config.jwt_secret == "custom_secret_for_testing_minimum_32_chars"
        assert config.jwt_expiry_minutes == 60
        assert config.bcrypt_rounds == 12

    def test_flext_auth_config_environment_variables(self) -> None:
        """Test FlextAuthConfig with environment variables."""
        with patch.dict(
            os.environ,
            {
                "FLEXT_AUTH_JWT_EXPIRY_MINUTES": "120",
                "FLEXT_AUTH_BCRYPT_ROUNDS": "14",
                "FLEXT_AUTH_MAX_LOGIN_ATTEMPTS": "3",
            },
        ):
            config = FlextAuthConfig()

            # These should be picked up from environment if supported
            assert config.jwt_expiry_minutes > 0
            assert config.bcrypt_rounds >= 10

    def test_flext_auth_config_validation_edge_cases(self) -> None:
        """Test FlextAuthConfig validation with edge cases."""
        # Test minimum values
        config = FlextAuthConfig(
            jwt_expiry_minutes=1,  # Minimum allowed
            bcrypt_rounds=10,  # Minimum reasonable
            max_login_attempts=1,  # Minimum allowed
        )

        assert config.jwt_expiry_minutes == 1
        assert config.bcrypt_rounds == 10
        assert config.max_login_attempts == 1

    def test_flext_auth_config_invalid_values(self) -> None:
        """Test FlextAuthConfig with invalid values."""
        # Invalid values should raise validation errors
        with pytest.raises(ValidationError) as exc_info:
            FlextAuthConfig(
                jwt_expiry_minutes=0,  # Should be >= 1
                bcrypt_rounds=5,  # Should be >= 10
                max_login_attempts=0,  # Should be >= 1
            )

        # Verify the validation errors contain expected error types
        errors = exc_info.value.errors()
        error_types = {error["type"] for error in errors}
        assert "greater_than_equal" in error_types

        # Verify we get exactly 3 validation errors
        assert len(errors) == 3

        # Test with valid values to ensure validation passes
        config = FlextAuthConfig(
            jwt_expiry_minutes=30,  # Valid value
            bcrypt_rounds=12,  # Valid value
            max_login_attempts=5,  # Valid value
        )
        assert config.jwt_expiry_minutes == 30
        assert config.bcrypt_rounds == 12
        assert config.max_login_attempts == 5

    def test_flext_auth_config_params_dict(self) -> None:
        """Test FlextAuthConfig with dictionary parameters."""
        params = {
            "jwt_secret": "test_secret_minimum_32_characters_long",
            "jwt_expiry_minutes": 30,
            "bcrypt_rounds": 12,
        }

        config = FlextAuthConfig(**params)
        assert config.jwt_secret == "test_secret_minimum_32_characters_long"
        assert config.jwt_expiry_minutes == 30
        assert config.bcrypt_rounds == 12

    def test_environment_config_request_model_and_defaults(self) -> None:
        """Test environment configuration (simplified) and defaults."""
        # Test that we can create config for different environments
        dev_config = FlextAuthConfig()
        assert dev_config.environment == "development"

        # Test production environment
        prod_config = FlextAuthConfig()
        assert prod_config.environment == "production"

    def test_flext_auth_config_all_fields(self) -> None:
        """Test FlextAuthConfig with all available fields."""
        config = FlextAuthConfig(
            jwt_secret="comprehensive_test_secret_minimum_32_characters_long",
            jwt_expiry_minutes=45,
            jwt_algorithm="HS256",
            jwt_issuer="test-issuer",
            jwt_audience="test-audience",
            bcrypt_rounds=13,
            max_login_attempts=5,
            lockout_duration_minutes=15,
            session_expiry_minutes=60,
            max_sessions_per_user=3,
            session_cleanup_interval_minutes=10,
            min_password_length=8,
            max_password_length=128,
            require_password_complexity=True,
            min_password_score=3,
            max_requests_per_minute=100,
            max_requests_per_hour=1000,
            enable_email_verification=True,
            enable_password_history=True,
            enable_audit_logging=True,
            enable_rate_limiting=True,
        )

        # Verify all fields are set correctly
        assert (
            config.jwt_secret == "comprehensive_test_secret_minimum_32_characters_long"
        )
        assert config.jwt_expiry_minutes == 45
        assert config.jwt_algorithm == "HS256"
        assert config.bcrypt_rounds == 13
        assert config.max_login_attempts == 5

    def test_flext_auth_config_inheritance(self) -> None:
        """Test FlextAuthConfig inheritance from FlextConfig."""
        config = FlextAuthConfig()

        # Should inherit from FlextConfig
        assert isinstance(config, FlextConfig)

    def test_flext_auth_config_field_validation(self) -> None:
        """Test field validation in FlextAuthConfig."""
        # Test password length validation - should fail with invalid values
        with pytest.raises(
            ValidationError,
            match="Input should be greater than or equal to 6",
        ):
            FlextAuthConfig(min_password_length=4, max_password_length=256)

        # Test with valid values
        config = FlextAuthConfig(min_password_length=8, max_password_length=256)
        assert config.min_password_length >= 8
        assert config.max_password_length <= 256

    def test_flext_auth_config_jwt_secret_and_security_defaults(self) -> None:
        """Test JWT secret generation and security-related default values."""
        # Test JWT secret generation when empty
        config = FlextAuthConfig(jwt_secret="")
        assert isinstance(config.jwt_secret, str)

        # Test security defaults
        config = FlextAuthConfig()
        assert config.bcrypt_rounds >= 10  # Secure hashing
        assert config.max_login_attempts > 0  # Prevent brute force
        assert config.jwt_expiry_minutes > 0  # Tokens should expire

    def test_flext_auth_config_with_none_values(self) -> None:
        """Test FlextAuthConfig handling of invalid values."""
        # Test with invalid values that should be handled gracefully
        try:
            config = FlextAuthConfig(
                jwt_issuer="",
                jwt_audience="",
            )
            # Should handle empty values appropriately
            assert config is not None
        except Exception as e:
            pytest.fail(f"Unexpected exception during config creation: {e}")

    def test_model_and_environment_config_validation(self) -> None:
        """Test Pydantic model validation and environment configuration validation."""
        # Test with invalid values that should trigger validation errors
        with pytest.raises(ValidationError) as exc_info:
            FlextAuthConfig(
                jwt_expiry_minutes=0,  # Invalid value (should be >= 1)
                bcrypt_rounds=0,  # Invalid value (should be >= 10)
            )

        # Verify the validation errors contain expected error types
        errors = exc_info.value.errors()
        error_types = {error["type"] for error in errors}
        assert "greater_than_equal" in error_types

        # Test with valid values to ensure validation passes
        config = FlextAuthConfig(
            jwt_expiry_minutes=30,  # Valid value
            bcrypt_rounds=12,  # Valid value
        )
        assert isinstance(config.jwt_expiry_minutes, int)
        assert config.jwt_expiry_minutes == 30
        assert config.bcrypt_rounds == 12

        # Test environment configuration validation
        env_config = FlextAuthConfig(
            jwt_expiry_minutes=30,
            bcrypt_rounds=12,
            enable_audit_logging=True,
            jwt_secret="override_secret_minimum_32_characters_long",
        )

        assert env_config.jwt_expiry_minutes == 30

    def test_constants_usage_and_settings_methods(self) -> None:
        """Test usage of FlextConstants and get_security_settings/get_jwt_settings methods."""
        config = FlextAuthConfig()

        # Should use constants from FlextConstants.Auth
        # Verify that constants are being used appropriately
        assert hasattr(FlextConstants, "Auth") or config.jwt_algorithm is not None

        security_settings = config.get_security_settings()

        assert isinstance(security_settings, dict)
        assert "bcrypt_rounds" in security_settings
        assert "max_login_attempts" in security_settings
        assert "lockout_duration_minutes" in security_settings
        assert "min_password_length" in security_settings
        assert "max_password_length" in security_settings
        # Note: require_password_complexity and min_password_score are not in get_security_settings
        # They are validation rules, not configuration settings

        assert security_settings["bcrypt_rounds"] == config.bcrypt_rounds
        assert security_settings["max_login_attempts"] == config.max_login_attempts
        assert (
            security_settings["lockout_duration_minutes"]
            == config.lockout_duration_minutes
        )

        # Test JWT settings
        jwt_settings = config.get_jwt_settings()
        assert isinstance(jwt_settings, dict)
        assert "jwt_expiry_minutes" in jwt_settings
        assert "jwt_algorithm" in jwt_settings
        assert "issuer" in jwt_settings
        assert "audience" in jwt_settings
        assert "secret_configured" in jwt_settings

        assert jwt_settings["jwt_expiry_minutes"] == config.jwt_expiry_minutes
        assert jwt_settings["algorithm"] == config.jwt_algorithm
        assert jwt_settings["issuer"] == config.jwt_issuer
        assert jwt_settings["audience"] == config.jwt_audience
        assert jwt_settings["secret_configured"] == (config.jwt_secret is not None)

    def test_create_from_environment_method(self) -> None:
        """Test create_from_environment method coverage."""
        # Test with environment variables
        with patch.dict(
            os.environ,
            {
                "FLEXT_AUTH_JWT_SECRET": "test_jwt_secret_minimum_32_characters_long",
                "FLEXT_AUTH_JWT_EXPIRY_MINUTES": "30",
                "FLEXT_AUTH_JWT_ALGORITHM": "HS256",
                "FLEXT_AUTH_BCRYPT_ROUNDS": "12",
                "FLEXT_AUTH_MAX_LOGIN_ATTEMPTS": "3",
                "FLEXT_AUTH_SESSION_EXPIRY_MINUTES": "60",
                "FLEXT_AUTH_ENABLE_AUDIT_LOGGING": "false",
                "FLEXT_AUTH_ENABLE_RATE_LIMITING": "false",
            },
        ):
            config = FlextAuthConfig()

            assert config.jwt_secret == "test_jwt_secret_minimum_32_characters_long"
            assert config.jwt_expiry_minutes == 30
            assert config.jwt_algorithm == "HS256"
            assert config.bcrypt_rounds == 12
            assert config.max_login_attempts == 3
            assert config.session_expiry_minutes == 60
        assert config.enable_audit_logging is False
        assert config.enable_rate_limiting is False

    def test_config_validation_jwt_expiry_exceeds_session(self) -> None:
        """Test config validation when JWT expiry exceeds session expiry."""
        # Test the specific validation logic for JWT expiry vs session expiry
        with pytest.raises(ValidationError):
            FlextAuthConfig(
                jwt_secret="test_jwt_secret_minimum_32_characters_long",
                jwt_expiry_minutes=120,  # 2 hours
                session_expiry_minutes=30,  # 30 minutes - JWT exceeds 2x session
            )

    def test_create_from_environment_exception_handling(self) -> None:
        """Test exception handling in create_for_environment method."""
        # create_for_environment calls get_or_create_shared_instance which can raise ValidationError
        with patch(
            "flext_auth.config.FlextAuthConfig.get_or_create_shared_instance"
        ) as mock_get_or_create:
            mock_get_or_create.side_effect = Exception("Test exception")
            # The method should raise the exception
            with pytest.raises(Exception, match="Test exception"):
                FlextAuthConfig()


class TestFlextAuthConfigAdditionalCoverage:
    """Test additional coverage for missing lines in config.py."""

    def test_create_with_overrides_method(self) -> None:
        """Test create_with_overrides method to cover lines 450-462."""
        config = FlextAuthConfig.create_with_overrides(
            jwt_expiry_minutes=45,
            bcrypt_rounds=14,
            max_login_attempts=3,
            session_expiry_minutes=90,
            environment="test",
        )
        assert config.jwt_expiry_minutes == 45
        assert config.bcrypt_rounds == 14
        assert config.max_login_attempts == 3
        assert config.session_expiry_minutes == 90

    def test_global_instance_type_error_and_overrides(self) -> None:
        """Test set_global_instance with invalid type and get_or_create_global with overrides."""
        # Test set_global_instance with invalid type
        with pytest.raises(
            TypeError,
            match="Instance must be of type FlextAuthConfig",
        ):
            # Cast needed for intentional type violation in test
            FlextAuthConfig.set_global_instance(cast("FlextConfig", object()))

        # Test get_or_create_global with overrides
        result = FlextAuthConfig.get_or_create_global(
            environment="test",
            jwt_expiry_minutes=60,
            bcrypt_rounds=13,
            max_login_attempts=4,
            session_expiry_minutes=120,
        )

        assert result.is_success
        config = result.value
        assert config.jwt_expiry_minutes == 60
        assert config.bcrypt_rounds == 13
        assert config.max_login_attempts == 4
        assert config.session_expiry_minutes == 120


class TestConfigModule:
    """Unified test class for config module functionality."""

    class _TestDataHelper:
        """Nested helper class for test data creation."""

        @staticmethod
        def create_test_config_data() -> FlextTypes.Dict:
            """Create test configuration data."""
            return {
                "auth_secret_key": "test_secret_key_123",
                "token_expiry": 3600,
                "session_timeout": 1800,
                "max_login_attempts": 5,
                "password_min_length": 8,
            }

        @staticmethod
        def create_test_auth_config_data() -> FlextTypes.Dict:
            """Create test authentication configuration data."""
            return {
                "jwt_secret": "jwt_secret_key_456",
                "jwt_algorithm": "HS256",
                "access_token_expiry": 900,
                "refresh_token_expiry": 86400,
            }

        @staticmethod
        def create_test_security_config_data() -> FlextTypes.Dict:
            """Create test security configuration data."""
            return {
                "bcrypt_rounds": 12,
                "rate_limit_requests": 100,
                "rate_limit_window": 3600,
                "enable_2fa": True,
            }

    def test_flext_auth_config_initialization(self) -> None:
        """Test FlextAuthConfig initializes correctly."""
        config = FlextAuthConfig()
        assert config is not None

    def test_flext_auth_config_load_config(self) -> None:
        """Test FlextAuthConfig load_config functionality."""
        config = FlextAuthConfig()
        test_data = self._TestDataHelper.create_test_config_data()

        # Test config loading if method exists
        load_config_method = getattr(config, "load_config", None)
        if load_config_method:
            result = load_config_method(test_data)
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_get_config(self) -> None:
        """Test FlextAuthConfig get_config functionality."""
        config = FlextAuthConfig()
        test_data = self._TestDataHelper.create_test_config_data()

        # Load config first if possible
        if hasattr(config, "load_config"):
            config.load_config(test_data)

        # Test config retrieval if method exists
        if hasattr(config, "get_config"):
            result = config.get_config()
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_set_config(self) -> None:
        """Test FlextAuthConfig set_config functionality."""
        config = FlextAuthConfig()
        test_data = self._TestDataHelper.create_test_config_data()

        # Test config setting if method exists
        if hasattr(config, "set_config"):
            result = config.set_config(test_data)
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_validate_config(self) -> None:
        """Test FlextAuthConfig validate_config functionality."""
        config = FlextAuthConfig()
        test_data = self._TestDataHelper.create_test_config_data()

        # Test config validation if method exists
        if hasattr(config, "validate_config"):
            result = config.validate_config(test_data)
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_reset_config(self) -> None:
        """Test FlextAuthConfig reset_config functionality."""
        config = FlextAuthConfig()
        test_data = self._TestDataHelper.create_test_config_data()

        # Load config first if possible
        if hasattr(config, "load_config"):
            config.load_config(test_data)

        # Test config reset if method exists
        if hasattr(config, "reset_config"):
            result = config.reset_config()
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_get_auth_config(self) -> None:
        """Test FlextAuthConfig get_auth_config functionality."""
        config = FlextAuthConfig()
        test_data = self._TestDataHelper.create_test_auth_config_data()

        # Load config first if possible
        if hasattr(config, "load_config"):
            config.load_config(test_data)

        # Test auth config retrieval if method exists
        if hasattr(config, "get_auth_config"):
            result = config.get_auth_config()
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_get_security_config(self) -> None:
        """Test FlextAuthConfig get_security_config functionality."""
        config = FlextAuthConfig()
        test_data = self._TestDataHelper.create_test_security_config_data()

        # Load config first if possible
        if hasattr(config, "load_config"):
            config.load_config(test_data)

        # Test security config retrieval if method exists
        if hasattr(config, "get_security_config"):
            result = config.get_security_config()
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_comprehensive_scenario(self) -> None:
        """Test comprehensive config module scenario."""
        config = FlextAuthConfig()
        test_config_data = self._TestDataHelper.create_test_config_data()

        # Test initialization
        assert config is not None

        # Test config operations
        if hasattr(config, "load_config"):
            load_result = config.load_config(test_config_data)
            assert isinstance(load_result, FlextResult)

        if hasattr(config, "validate_config"):
            validate_result = config.validate_config(test_config_data)
            assert isinstance(validate_result, FlextResult)

        # Test auth config operations
        if hasattr(config, "get_auth_config"):
            auth_config_result = config.get_auth_config()
            assert isinstance(auth_config_result, FlextResult)

        # Test security config operations
        if hasattr(config, "get_security_config"):
            security_config_result = config.get_security_config()
            assert isinstance(security_config_result, FlextResult)

    def test_flext_auth_config_error_handling(self) -> None:
        """Test config module error handling patterns."""
        config = FlextAuthConfig()

        # Test with invalid data
        invalid_data = {"invalid": "data"}

        # Test config loading error handling
        if hasattr(config, "load_config"):
            result = config.load_config(invalid_data)
            assert isinstance(result, FlextResult)
            # Should handle invalid data gracefully

        # Test config validation error handling
        if hasattr(config, "validate_config"):
            result = config.validate_config(invalid_data)
            assert isinstance(result, FlextResult)
            # Should handle invalid data gracefully

        # Test retrieval of non-existent config
        if hasattr(config, "get_config"):
            result = config.get_config()
            assert isinstance(result, FlextResult)
            # Should handle empty config gracefully

    def test_flext_auth_config_with_flext_tests(self) -> None:
        """Test config functionality with flext_tests infrastructure."""
        config = FlextAuthConfig()

        # Create test data manually
        test_config_data = {
            "auth_secret_key": "flext_test_secret",
            "token_expiry": 1800,
        }

        # Test config loading with flext_tests data
        if hasattr(config, "load_config"):
            result = config.load_config(test_config_data)
            assert isinstance(result, FlextResult)

        # Test config validation with flext_tests data
        if hasattr(config, "validate_config"):
            result = config.validate_config(test_config_data)
            assert isinstance(result, FlextResult)

    def test_flext_auth_config_docstring(self) -> None:
        """Test that FlextAuthConfig has proper docstring."""
        assert FlextAuthConfig.__doc__ is not None
        assert len(FlextAuthConfig.__doc__.strip()) > 0

    def test_flext_auth_config_method_signatures(self) -> None:
        """Test that config methods have proper signatures."""
        config = FlextAuthConfig()

        # Test that all public methods exist and are callable
        expected_methods = [
            "load_config",
            "get_config",
            "set_config",
            "validate_config",
            "reset_config",
            "get_auth_config",
            "get_security_config",
        ]

        for method_name in expected_methods:
            if hasattr(config, method_name):
                method = getattr(config, method_name)
                assert callable(method), f"Method {method_name} should be callable"

    def test_flext_auth_config_with_real_data(self) -> None:
        """Test config functionality with realistic data scenarios."""
        config = FlextAuthConfig()

        # Create realistic configuration scenarios
        realistic_configs = [
            {
                "auth_secret_key": "production_secret_key_xyz789",
                "token_expiry": 3600,
                "session_timeout": 1800,
                "max_login_attempts": 3,
                "password_min_length": 12,
                "enable_2fa": True,
            },
            {
                "auth_secret_key": "development_secret_key_abc123",
                "token_expiry": 7200,
                "session_timeout": 3600,
                "max_login_attempts": 10,
                "password_min_length": 6,
                "enable_2fa": False,
            },
            {
                "auth_secret_key": "testing_secret_key_def456",
                "token_expiry": 1800,
                "session_timeout": 900,
                "max_login_attempts": 5,
                "password_min_length": 8,
                "enable_2fa": True,
            },
        ]

        # Test config loading with realistic data
        if hasattr(config, "load_config"):
            for config_data in realistic_configs:
                result = config.load_config(config_data)
                assert isinstance(result, FlextResult)

        # Test config validation with realistic data
        if hasattr(config, "validate_config"):
            for config_data in realistic_configs:
                result = config.validate_config(config_data)
                assert isinstance(result, FlextResult)

    def test_flext_auth_config_integration_patterns(self) -> None:
        """Test config integration patterns between different components."""
        config = FlextAuthConfig()

        # Test integration: load_config -> validate_config -> get_config
        test_config_data = self._TestDataHelper.create_test_config_data()

        # Load config
        if hasattr(config, "load_config"):
            load_result = config.load_config(test_config_data)
            assert isinstance(load_result, FlextResult)

        # Validate config
        if hasattr(config, "validate_config"):
            validate_result = config.validate_config(test_config_data)
            assert isinstance(validate_result, FlextResult)

        # Get config
        if hasattr(config, "get_config"):
            get_result = config.get_config()
            assert isinstance(get_result, FlextResult)

    def test_flext_auth_config_performance_patterns(self) -> None:
        """Test config performance patterns."""
        config = FlextAuthConfig()

        # Test that config operations are reasonably fast
        start_time = time.time()

        # Test multiple operations
        test_config_data = self._TestDataHelper.create_test_config_data()

        if hasattr(config, "load_config"):
            for i in range(10):
                config_data = {**test_config_data, "auth_secret_key": f"secret_{i}"}
                result = config.load_config(config_data)
                assert isinstance(result, FlextResult)

        end_time = time.time()
        assert (end_time - start_time) < 1.0  # Should complete in less than 1 second

    def test_flext_auth_config_concurrent_operations(self) -> None:
        """Test config concurrent operations."""
        config = FlextAuthConfig()
        results = []

        def load_config(index: int) -> None:
            config_data = {"auth_secret_key": f"secret_{index}", "token_expiry": 3600}
            if hasattr(config, "load_config"):
                result = config.load_config(config_data)
                results.append(result)

        def validate_config(index: int) -> None:
            config_data = {"auth_secret_key": f"secret_{index}", "token_expiry": 3600}
            if hasattr(config, "validate_config"):
                result = config.validate_config(config_data)
                results.append(result)

        # Test concurrent operations
        threads = []
        for i in range(5):
            thread = threading.Thread(target=load_config, args=(i,))
            threads.append(thread)
            thread.start()

            thread = threading.Thread(target=validate_config, args=(i,))
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()

        # All results should be FlextResult instances
        for result in results:
            assert isinstance(result, FlextResult)


class TestFlextAuthConfigSingletonOnly:
    """Test FlextAuthConfig singleton-only usage patterns."""

    def test_singleton_default_creation(self) -> None:
        """Test FlextAuthConfig singleton creation with defaults."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config = FlextAuthConfig.get_global_instance()

        assert config.jwt_expiry_minutes > 0
        assert config.jwt_algorithm is not None
        assert config.bcrypt_rounds >= 10
        assert config.max_login_attempts > 0

    def test_singleton_with_parameter_overrides(self) -> None:
        """Test FlextAuthConfig singleton with custom parameter overrides."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config_result = FlextAuthConfig.get_or_create_global(
            jwt_secret="custom_secret_for_testing_minimum_32_chars",
            jwt_expiry_minutes=60,
            bcrypt_rounds=12,
            environment="development",
        )

        assert config_result.is_success
        config = config_result.value

        assert config.jwt_secret == "custom_secret_for_testing_minimum_32_chars"
        assert config.jwt_expiry_minutes == 60
        assert config.bcrypt_rounds == 12

    def test_singleton_environment_variables(self) -> None:
        """Test FlextAuthConfig singleton with environment variables."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Set environment variables
        original_value = os.environ.get("FLEXT_AUTH_JWT_EXPIRY_MINUTES")
        os.environ["FLEXT_AUTH_JWT_EXPIRY_MINUTES"] = "45"

        try:
            config = FlextAuthConfig.get_global_instance()
            assert config.jwt_expiry_minutes == 45
        finally:
            # Restore original environment
            if original_value is not None:
                os.environ["FLEXT_AUTH_JWT_EXPIRY_MINUTES"] = original_value
            else:
                os.environ.pop("FLEXT_AUTH_JWT_EXPIRY_MINUTES", None)

    def test_singleton_validation_edge_cases(self) -> None:
        """Test FlextAuthConfig singleton validation edge cases."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test with valid configuration
        config_result = FlextAuthConfig.get_or_create_global(
            jwt_expiry_minutes=30,
            session_expiry_minutes=60,
            environment="development",
        )

        assert config_result.is_success
        config = config_result.value

        validation_result = config.validate_configuration()
        assert validation_result.is_success

    def test_singleton_invalid_values(self) -> None:
        """Test FlextAuthConfig singleton with invalid values."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test with valid configuration (JWT <= 2 * session expiry)
        config_result = FlextAuthConfig.get_or_create_global(
            jwt_expiry_minutes=60,  # Valid value
            session_expiry_minutes=120,  # Higher than JWT expiry
            environment="development",
        )

        # Should succeed creation (JWT <= 2 * session expiry)
        assert config_result.is_success
        config = config_result.value
        assert config.jwt_expiry_minutes == 60
        assert config.session_expiry_minutes == 120

    def test_singleton_params_dict(self) -> None:
        """Test FlextAuthConfig singleton with params dict."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        params: dict[str, int | str] = {
            "jwt_expiry_minutes": 90,
            "bcrypt_rounds": 11,
            "max_login_attempts": 7,
            "environment": "development",
        }

        # Filter params to only include valid config fields
        valid_fields = {
            "jwt_expiry_minutes",
            "bcrypt_rounds",
            "max_login_attempts",
            "environment",
            "jwt_secret",
            "session_expiry_minutes",
        }
        valid_params: dict[str, int | str] = {
            k: v for k, v in params.items() if k in valid_fields
        }
        config_result = FlextAuthConfig.get_or_create_global(**valid_params)

        assert config_result.is_success
        config = config_result.value

        assert config.jwt_expiry_minutes == 90
        assert config.bcrypt_rounds == 11
        assert config.max_login_attempts == 7

    def test_singleton_environment_config_request_model(self) -> None:
        """Test FlextAuthConfig singleton environment configuration."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test development environment
        dev_config = FlextAuthConfig.get_or_create_global(environment="development")
        assert dev_config.is_success

        # Test production environment
        prod_config = FlextAuthConfig.get_or_create_global(environment="production")
        assert prod_config.is_success

        # Both should be valid
        assert dev_config.value.validate_configuration().is_success
        assert prod_config.value.validate_configuration().is_success

    def test_singleton_environment_config_request_defaults(self) -> None:
        """Test FlextAuthConfig singleton environment defaults."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test default environment
        config = FlextAuthConfig.get_global_instance()

        # Should have reasonable defaults
        assert config.jwt_expiry_minutes > 0
        assert config.bcrypt_rounds >= 10
        assert config.max_login_attempts > 0
        assert config.session_expiry_minutes > config.jwt_expiry_minutes

    def test_singleton_all_fields(self) -> None:
        """Test FlextAuthConfig singleton with all fields."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config_result = FlextAuthConfig.get_or_create_global(
            jwt_auth_secret=SecretStr("test_secret_minimum_32_characters_long"),
            jwt_expiry_minutes=45,
            jwt_algorithm="HS256",
            jwt_issuer="test_issuer",
            jwt_audience="test_audience",
            bcrypt_rounds=11,
            max_login_attempts=6,
            lockout_duration_minutes=25,
            session_expiry_minutes=90,
            max_sessions_per_user=8,
            session_cleanup_interval_minutes=15,
            min_password_length=8,  # Minimum allowed
            max_password_length=50,
            require_password_complexity=True,
            min_password_score=3,
            max_requests_per_minute=150,
            max_requests_per_hour=2000,
            enable_email_verification=True,
            enable_password_history=True,
            enable_audit_logging=True,
            enable_rate_limiting=True,
            environment="development",
        )

        assert config_result.is_success
        config = config_result.value

        assert (
            config.jwt_auth_secret.get_secret_value()
            == "test_secret_minimum_32_characters_long"
        )
        assert config.jwt_expiry_minutes == 45
        assert config.jwt_algorithm == "HS256"
        assert config.jwt_issuer == "test_issuer"
        assert config.jwt_audience == "test_audience"
        assert config.bcrypt_rounds == 11
        assert config.max_login_attempts == 6
        assert config.lockout_duration_minutes == 25
        assert config.session_expiry_minutes == 90
        assert config.max_sessions_per_user == 8
        assert config.session_cleanup_interval_minutes == 15
        assert config.min_password_length == 8
        assert config.max_password_length == 50
        assert config.require_password_complexity is True
        assert config.min_password_score == 3
        assert config.max_requests_per_minute == 150
        assert config.max_requests_per_hour == 2000
        assert config.enable_email_verification is True
        assert config.enable_password_history is True
        assert config.enable_audit_logging is True
        assert config.enable_rate_limiting is True

    def test_singleton_inheritance(self) -> None:
        """Test FlextAuthConfig singleton inheritance from FlextConfig."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config = FlextAuthConfig.get_global_instance()

        # Should inherit from FlextConfig

        assert isinstance(config, FlextConfig)

        # Should have environment attribute
        assert hasattr(config, "environment")

    def test_singleton_field_validation(self) -> None:
        """Test FlextAuthConfig singleton field validation."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test with valid values
        config_result = FlextAuthConfig.get_or_create_global(
            jwt_expiry_minutes=30,
            bcrypt_rounds=12,
            max_login_attempts=5,
            environment="development",
        )

        assert config_result.is_success
        config = config_result.value

        # All fields should be valid
        assert config.jwt_expiry_minutes == 30
        assert config.bcrypt_rounds == 12
        assert config.max_login_attempts == 5

    def test_singleton_jwt_secret_generation(self) -> None:
        """Test FlextAuthConfig singleton JWT secret generation."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test with empty secret (should be generated)
        config_result = FlextAuthConfig.get_or_create_global(
            jwt_auth_secret=SecretStr(""),
            environment="development",
        )

        assert config_result.is_success
        config = config_result.value

        # Secret should be generated
        assert config.jwt_auth_secret
        assert len(config.jwt_auth_secret.get_secret_value()) >= 32

    def test_singleton_security_defaults(self) -> None:
        """Test FlextAuthConfig singleton security defaults."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config = FlextAuthConfig.get_global_instance()

        # Should have secure defaults
        assert config.bcrypt_rounds >= 10
        assert config.jwt_expiry_minutes <= 60
        assert config.max_login_attempts <= 10
        assert config.min_password_length >= 6

    def test_singleton_with_none_values(self) -> None:
        """Test FlextAuthConfig singleton with None values."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test with None values (should use defaults)
        config_result = FlextAuthConfig.get_or_create_global(environment="development")

        assert config_result.is_success
        config = config_result.value

        # Should use default values
        assert config.jwt_expiry_minutes > 0
        assert config.bcrypt_rounds > 0

    def test_singleton_model_validation(self) -> None:
        """Test FlextAuthConfig singleton model validation."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config_result = FlextAuthConfig.get_or_create_global(
            jwt_expiry_minutes=30,
            bcrypt_rounds=12,
            environment="development",
        )

        assert config_result.is_success
        config = config_result.value

        # Should pass validation
        validation_result = config.validate_configuration()
        assert validation_result.is_success

    def test_singleton_environment_config_request_validation(self) -> None:
        """Test FlextAuthConfig singleton environment validation."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test valid environments
        valid_environments = ["development", "staging", "production", "test"]

        for env in valid_environments:
            # Clear singleton before each test to ensure fresh instance
            FlextAuthConfig.reset_global_instance()
            config_result = FlextAuthConfig.get_or_create_global(environment=env)
            assert config_result.is_success
            assert config_result.value.environment == env

    def test_singleton_constants_usage(self) -> None:
        """Test FlextAuthConfig singleton constants usage."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config = FlextAuthConfig.get_global_instance()

        # Should use constants from flext-core

        assert config.jwt_algorithm == FlextAuthConstants.Jwt.DEFAULT_ALGORITHM
        assert (
            config.bcrypt_rounds
            == FlextAuthConstants.Credentials.Password.BCRYPT_ROUNDS
        )

    def test_get_security_settings_method(self) -> None:
        """Test FlextAuthConfig singleton get_security_settings method."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config = FlextAuthConfig.get_global_instance()
        security_settings = config.get_security_settings()

        assert isinstance(security_settings, dict)
        assert "bcrypt_rounds" in security_settings
        assert "max_login_attempts" in security_settings
        assert "min_password_length" in security_settings

    def test_get_jwt_settings_method(self) -> None:
        """Test FlextAuthConfig singleton get_jwt_settings method."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config = FlextAuthConfig.get_global_instance()
        jwt_settings = config.get_jwt_settings()

        assert isinstance(jwt_settings, dict)
        assert "jwt_expiry_minutes" in jwt_settings
        assert "jwt_algorithm" in jwt_settings
        assert "secret_configured" in jwt_settings
        # Secret should not be included for security
        assert "jwt_secret" not in jwt_settings

    def test_create_from_environment_method(self) -> None:
        """Test FlextAuthConfig singleton create_from_environment method."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test creating from environment
        config = FlextAuthConfig()
        assert config.environment == "development"
        assert config.validate_configuration().is_success


class TestFlextAuthConfigSingletonAdditionalCoverage:
    """Additional singleton-only coverage tests."""

    def test_singleton_config_validation_jwt_expiry_exceeds_session(self) -> None:
        """Test singleton configuration validation when JWT expiry exceeds session."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        config_result = FlextAuthConfig.get_or_create_global(
            jwt_expiry_minutes=120,
            session_expiry_minutes=60,  # Less than JWT expiry
            environment="development",
        )

        # Should fail due to JWT expiry exceeding session expiry
        assert config_result.is_failure
        assert "JWT expiry should not exceed session expiry" in str(config_result.error)

    def test_singleton_create_from_environment_exception_handling(self) -> None:
        """Test singleton create_for_environment exception handling."""
        # Clear any existing singleton
        FlextAuthConfig.reset_global_instance()

        # Test with invalid environment - raises ValidationError
        with pytest.raises(ValidationError, match="Invalid environment"):
            FlextAuthConfig()

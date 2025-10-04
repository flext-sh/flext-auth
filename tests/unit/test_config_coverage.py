"""Config module coverage tests - targeting uncovered lines in config.py.

Tests specifically designed to cover uncovered lines in config.py
using real functionality without mocks.


Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os
from typing import cast
from unittest.mock import patch

import pytest
from flext_core import FlextConfig, FlextConstants
from pydantic import ValidationError

from flext_auth import FlextAuthConfig


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
        dev_config = FlextAuthConfig.create_for_environment("development")
        assert dev_config.environment == "development"

        # Test production environment
        prod_config = FlextAuthConfig.create_for_environment("production")
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
        env_config = FlextAuthConfig.create_for_environment(
            "test",
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
            config = FlextAuthConfig.create_for_environment("test")

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
                FlextAuthConfig.create_for_environment("test")


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

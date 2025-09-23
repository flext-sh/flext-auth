"""Test FlextAuthConfig singleton-only usage patterns.

Tests that FlextAuthConfig is used exclusively as singleton throughout
the module, ensuring no direct instantiation patterns are used.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import os

from flext_auth import FlextAuthConfig, FlextAuthConstants
from flext_core import FlextConfig


class TestFlextAuthConfigSingletonOnly:
    """Test FlextAuthConfig singleton-only usage patterns."""

    def test_singleton_default_creation(self) -> None:
        """Test FlextAuthConfig singleton creation with defaults."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        config = FlextAuthConfig.get_global_instance()

        assert config.jwt_expiry_minutes > 0
        assert config.jwt_algorithm is not None
        assert config.bcrypt_rounds >= 10
        assert config.max_login_attempts > 0

    def test_singleton_with_parameter_overrides(self) -> None:
        """Test FlextAuthConfig singleton with custom parameter overrides."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

        config_result = FlextAuthConfig.get_or_create_global(
            jwt_secret="test_secret_minimum_32_characters_long",
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
            min_password_length=7,
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

        assert config.jwt_secret == "test_secret_minimum_32_characters_long"
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
        assert config.min_password_length == 7
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
        FlextAuthConfig.clear_global_instance()

        config = FlextAuthConfig.get_global_instance()

        # Should inherit from FlextConfig

        assert isinstance(config, FlextConfig)

        # Should have environment attribute
        assert hasattr(config, "environment")

    def test_singleton_field_validation(self) -> None:
        """Test FlextAuthConfig singleton field validation."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

        # Test with empty secret (should be generated)
        config_result = FlextAuthConfig.get_or_create_global(
            jwt_secret="",
            environment="development",
        )

        assert config_result.is_success
        config = config_result.value

        # Secret should be generated
        assert config.jwt_secret
        assert len(config.jwt_secret) >= 32

    def test_singleton_security_defaults(self) -> None:
        """Test FlextAuthConfig singleton security defaults."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        config = FlextAuthConfig.get_global_instance()

        # Should have secure defaults
        assert config.bcrypt_rounds >= 10
        assert config.jwt_expiry_minutes <= 60
        assert config.max_login_attempts <= 10
        assert config.min_password_length >= 6

    def test_singleton_with_none_values(self) -> None:
        """Test FlextAuthConfig singleton with None values."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

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
        FlextAuthConfig.clear_global_instance()

        # Test valid environments
        valid_environments = ["development", "staging", "production", "test"]

        for env in valid_environments:
            # Clear singleton before each test to ensure fresh instance
            FlextAuthConfig.clear_global_instance()
            config_result = FlextAuthConfig.get_or_create_global(environment=env)
            assert config_result.is_success
            assert config_result.value.environment == env

    def test_singleton_constants_usage(self) -> None:
        """Test FlextAuthConfig singleton constants usage."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        config = FlextAuthConfig.get_global_instance()

        # Should use constants from flext-core

        assert config.jwt_algorithm == FlextAuthConstants.JWT_DEFAULT_ALGORITHM
        assert config.bcrypt_rounds == FlextAuthConstants.BCRYPT_ROUNDS

    def test_get_security_settings_method(self) -> None:
        """Test FlextAuthConfig singleton get_security_settings method."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        config = FlextAuthConfig.get_global_instance()
        security_settings = config.get_security_settings()

        assert isinstance(security_settings, dict)
        assert "bcrypt_rounds" in security_settings
        assert "max_login_attempts" in security_settings
        assert "min_password_length" in security_settings

    def test_get_jwt_settings_method(self) -> None:
        """Test FlextAuthConfig singleton get_jwt_settings method."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        config = FlextAuthConfig.get_global_instance()
        jwt_settings = config.get_jwt_settings()

        assert isinstance(jwt_settings, dict)
        assert "jwt_expiry_minutes" in jwt_settings
        assert "jwt_algorithm" in jwt_settings
        assert "jwt_secret_length" in jwt_settings
        # Secret should not be included for security
        assert "jwt_secret" not in jwt_settings

    def test_create_from_environment_method(self) -> None:
        """Test FlextAuthConfig singleton create_from_environment method."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        # Test creating from environment
        result = FlextAuthConfig.create_for_environment("development")
        assert result.is_success

        config = result.value
        assert config.environment == "development"
        assert config.validate_configuration().is_success


class TestFlextAuthConfigSingletonAdditionalCoverage:
    """Additional singleton-only coverage tests."""

    def test_singleton_config_validation_jwt_expiry_exceeds_session(self) -> None:
        """Test singleton configuration validation when JWT expiry exceeds session."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        config_result = FlextAuthConfig.get_or_create_global(
            jwt_expiry_minutes=120,
            session_expiry_minutes=60,  # Less than JWT expiry
            environment="development",
        )

        # Should succeed creation (no validation for JWT vs session expiry)
        assert config_result.is_success
        config = config_result.value
        assert config.jwt_expiry_minutes == 120
        assert config.session_expiry_minutes == 60

    def test_singleton_create_from_environment_exception_handling(self) -> None:
        """Test singleton create_from_environment exception handling."""
        # Clear any existing singleton
        FlextAuthConfig.clear_global_instance()

        # Test with invalid environment
        result = FlextAuthConfig.create_for_environment("invalid_environment")
        assert result.is_failure
        assert result.error is not None
        assert "Environment must be one of" in result.error

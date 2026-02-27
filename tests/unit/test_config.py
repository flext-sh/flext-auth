"""Config module tests - basic functionality tests.

Tests for FlextAuthSettings using real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import FlextAuthJwtProvider, FlextAuthSettings
from flext_auth.providers.jwt_token_generator import FlextAuthJwtTokenGenerator


class TestFlextAuthSettingsBasic:
    """Basic tests for FlextAuthSettings functionality."""

    def test_config_creation(self) -> None:
        """Test basic config creation."""
        config = FlextAuthSettings()
        assert isinstance(config, FlextAuthSettings)
        assert config.expiry_minutes > 0
        assert config.algorithm is not None

    def test_config_with_custom_values(self) -> None:
        """Test config with custom values."""
        config = FlextAuthSettings(
            expiry_minutes=60,
            hash_rounds=12,
        )
        assert config.expiry_minutes == 60
        assert config.hash_rounds == 12

    def test_config_validation(self) -> None:
        """Test config validation."""
        # Should work with valid values
        config = FlextAuthSettings(expiry_minutes=30)
        assert config.expiry_minutes == 30

    def test_global_instance(self) -> None:
        """Test global instance functionality."""
        # This should work with the AutoConfig pattern
        result = FlextAuthSettings.get_or_create_global()
        assert result.is_success
        config = result.value
        assert isinstance(config, FlextAuthSettings)


class TestJwtTokenGenerator:
    """Test JWT token generator functionality."""

    def test_generate_token_missing_config(self) -> None:
        """Test token generation with missing configuration."""
        # Arrange: provider with no config
        provider = FlextAuthJwtProvider(config=None)
        generator = FlextAuthJwtTokenGenerator(provider)

        # Act
        result = generator.generate_token(identity_id="user-123")

        # Assert: should fail due to missing secret_key
        assert result.is_failure
        assert "not configured" in (result.error or "").lower()

    def test_generate_token_success(self) -> None:
        """Test successful token generation."""
        # Arrange: provider with valid JWT config
        config = {
            "secret_key": "test-secret-key-for-jwt-minimum-32-chars",
            "algorithm": "HS256",
            "expiry_minutes": 30,
            "issuer": "flext-auth-test",
        }
        provider = FlextAuthJwtProvider(config=config)
        generator = FlextAuthJwtTokenGenerator(provider)

        # Act
        result = generator.generate_token(identity_id="user-456")

        # Assert: should succeed with a JWT string
        assert result.is_success
        token = result.value
        assert isinstance(token, str)
        assert len(token) > 0
        # JWT tokens have 3 dot-separated parts
        assert token.count(".") == 2

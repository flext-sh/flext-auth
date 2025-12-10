"""Config module tests - basic functionality tests.

Tests for FlextAuthConfig using real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from flext_auth import FlextAuthConfig
from flext_auth.providers.jwt import FlextAuthJwtProvider, FlextAuthJwtTokenGenerator


class TestFlextAuthConfigBasic:
    """Basic tests for FlextAuthConfig functionality."""

    def test_config_creation(self) -> None:
        """Test basic config creation."""
        config = FlextAuthConfig()
        assert isinstance(config, FlextAuthConfig)
        assert config.expiry_minutes > 0
        assert config.algorithm is not None

    def test_config_with_custom_values(self) -> None:
        """Test config with custom values."""
        config = FlextAuthConfig(
            expiry_minutes=60,
            hash_rounds=12,
        )
        assert config.expiry_minutes == 60
        assert config.hash_rounds == 12

    def test_config_validation(self) -> None:
        """Test config validation."""
        # Should work with valid values
        config = FlextAuthConfig(expiry_minutes=30)
        assert config.expiry_minutes == 30

        # Should fail with invalid values
        with pytest.raises(ValidationError):
            FlextAuthConfig(expiry_minutes=0)  # Too low

    def test_global_instance(self) -> None:
        """Test global instance functionality."""
        # This should work with the AutoConfig pattern
        result = FlextAuthConfig.get_or_create_global()
        assert result.is_success
        config = result.value
        assert isinstance(config, FlextAuthConfig)


class TestJwtTokenGenerator:
    """Test JWT token generator functionality."""

    def test_generate_token_missing_config(self) -> None:
        """Test token generation with missing configuration."""
        # Create provider with minimal config (missing secret)
        provider = FlextAuthJwtProvider({"algorithm": "HS256"})
        generator = FlextAuthJwtTokenGenerator(provider)

        # Test missing secret key
        result = generator.generate_token("user123")
        assert not result.is_success
        assert "secret key" in str(result.error).lower()

    def test_generate_token_success(self) -> None:
        """Test successful token generation."""
        config = {
            "secret_key": "test_secret_key_for_jwt_generation",
            "algorithm": "HS256",
            "issuer": "test_issuer",
            "audience": "test_audience",
            "expiry_minutes": 60,
        }
        provider = FlextAuthJwtProvider(config)
        generator = FlextAuthJwtTokenGenerator(provider)

        result = generator.generate_token("user123")
        assert result.is_success
        token = result.value
        assert isinstance(token, str)
        assert len(token) > 0

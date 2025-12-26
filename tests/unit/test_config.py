"""Config module tests - basic functionality tests.

Tests for FlextAuthSettings using real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError
from pydantic_settings import BaseSettings

from flext_auth import FlextAuthSettings


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
        result = FlextAuthSettings.get_or_create_global(config_class=BaseSettings)
        assert result.is_success
        config = result.value
        assert isinstance(config, FlextAuthSettings)


class TestJwtTokenGenerator:
    """Test JWT token generator functionality."""

    @pytest.mark.skip(reason="Requires concrete JWT provider implementation")
    def test_generate_token_missing_config(self) -> None:
        """Test token generation with missing configuration."""
        # TODO: Implement when concrete JWT provider is available

    @pytest.mark.skip(reason="Requires concrete JWT provider implementation")
    def test_generate_token_success(self) -> None:
        """Test successful token generation."""
        # TODO: Implement when concrete JWT provider is available

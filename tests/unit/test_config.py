"""Config module tests - basic functionality tests.

Tests for FlextAuthSettings using real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_tests import tm

from flext_auth import (
    FlextAuthJwtProvider,
    FlextAuthJwtTokenGenerator,
    FlextAuthSettings,
)


def _require_settings() -> FlextAuthSettings:
    result = FlextAuthSettings.get_or_create_global()
    tm.ok(result)
    return result.value


class TestFlextAuthSettingsBasic:
    """Basic tests for FlextAuthSettings functionality."""

    def test_config_creation(self) -> None:
        """Test basic config creation."""
        config = _require_settings()
        tm.that(config, is_=FlextAuthSettings)
        tm.that(config.expiry_minutes, gt=0)
        tm.that(config.algorithm, is_=str)

    def test_config_with_custom_values(self) -> None:
        """Test config with custom values."""
        base_config = _require_settings()
        config = base_config.model_copy(
            update={"expiry_minutes": 60, "hash_rounds": 12}
        )
        tm.that(config.expiry_minutes, eq=60)
        tm.that(config.hash_rounds, eq=12)

    def test_config_validation(self) -> None:
        """Test config validation."""
        base_config = _require_settings()
        config = base_config.model_copy(update={"expiry_minutes": 30})
        tm.that(config.expiry_minutes, eq=30)

    def test_global_instance(self) -> None:
        """Test global instance functionality."""
        config = _require_settings()
        tm.that(config, is_=FlextAuthSettings)


class TestJwtTokenGenerator:
    """Test JWT token generator functionality."""

    def test_generate_token_missing_config(self) -> None:
        """Test token generation with missing configuration."""
        provider = FlextAuthJwtProvider(config=None)
        generator = FlextAuthJwtTokenGenerator(provider)
        result = generator.generate_token(identity_id="user-123")
        tm.fail(result, contains="not configured")

    def test_generate_token_success(self) -> None:
        """Test successful token generation."""
        config = {
            "secret_key": "test-secret-key-for-jwt-minimum-32-chars",
            "algorithm": "HS256",
            "expiry_minutes": 30,
            "issuer": "flext-auth-test",
        }
        provider = FlextAuthJwtProvider(config=config)
        generator = FlextAuthJwtTokenGenerator(provider)
        result = generator.generate_token(identity_id="user-456")
        tm.ok(result)
        tm.that(result.value, is_=str)
        token_text = str(result.value)
        tm.that(len(token_text), gt=0)
        tm.that(token_text.count("."), eq=2)

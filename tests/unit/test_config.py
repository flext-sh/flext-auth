"""Config module tests - basic functionality tests.

Tests for FlextAuthSettings using real functionality without mocks.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import (
    FlextAuthJwtProvider,
    FlextAuthJwtTokenGenerator,
    FlextAuthSettings,
)
from tests import u


def _require_settings() -> FlextAuthSettings:
    return FlextAuthSettings.fetch_global()


class TestFlextAuthSettingsBasic:
    """Basic tests for FlextAuthSettings functionality."""

    def test_config_creation(self) -> None:
        """Test basic settings creation."""
        settings = _require_settings()
        u.Tests.Matchers.that(settings, is_=FlextAuthSettings)
        u.Tests.Matchers.that(settings.expiry_minutes, gt=0)
        u.Tests.Matchers.that(settings.algorithm, is_=str)

    def test_config_with_custom_values(self) -> None:
        """Test settings with custom values."""
        base_config = _require_settings()
        settings = base_config.model_copy(
            update={"expiry_minutes": 60, "hash_rounds": 12},
        )
        u.Tests.Matchers.that(settings.expiry_minutes, eq=60)
        u.Tests.Matchers.that(settings.hash_rounds, eq=12)

    def test_config_validation(self) -> None:
        """Test settings validation."""
        base_config = _require_settings()
        settings = base_config.model_copy(update={"expiry_minutes": 30})
        u.Tests.Matchers.that(settings.expiry_minutes, eq=30)

    def test_global_instance(self) -> None:
        """Test global instance functionality."""
        settings = _require_settings()
        u.Tests.Matchers.that(settings, is_=FlextAuthSettings)


class TestJwtTokenGenerator:
    """Test JWT token generator functionality."""

    def test_generate_token_missing_config(self) -> None:
        """Test token generation with missing configuration."""
        provider = FlextAuthJwtProvider(settings=None)
        generator = FlextAuthJwtTokenGenerator(provider)
        result = generator.generate_token(identity_id="user-123")
        assert result.failure
        assert result.error is not None
        assert "not configured" in result.error

    def test_generate_token_success(self) -> None:
        """Test successful token generation."""
        settings: dict[str, str | int] = {
            "secret_key": "test-secret-key-for-jwt-minimum-32-chars",
            "algorithm": "HS256",
            "expiry_minutes": 30,
            "issuer": "flext-auth-test",
        }
        provider = FlextAuthJwtProvider(settings=settings)
        generator = FlextAuthJwtTokenGenerator(provider)
        result = generator.generate_token(identity_id="user-456")
        assert result.success
        assert result.value is not None
        u.Tests.Matchers.that(result.value, is_=str)
        token_text = str(result.value)
        u.Tests.Matchers.that(len(token_text), gt=0)
        u.Tests.Matchers.that(token_text.count("."), eq=2)

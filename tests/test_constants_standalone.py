"""Unit tests for FlextAuthConstants standalone functionality.

Test consolidated constants without external dependencies.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth.constants import FlextAuthConstants


class TestFlextAuthConstantsStandalone:
    """Test standalone constants functionality."""

    def test_consolidated_constants_pattern(self) -> None:
        """Test the single consolidated class pattern."""
        # Test direct access to constants
        assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS == 5
        assert FlextAuthConstants.TOKEN_TYPE_ACCESS == "access"
        assert FlextAuthConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"

    def test_nested_class_backward_compatibility(self) -> None:
        """Test nested class access for backward compatibility."""
        # Test nested class access patterns
        assert FlextAuthConstants.TokenTypes.ACCESS == "access"
        assert FlextAuthConstants.TokenTypes.REFRESH == "refresh"
        assert FlextAuthConstants.UserRoles.ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert FlextAuthConstants.Security.DEFAULT_MAX_LOGIN_ATTEMPTS == 5

    def test_semantic_constants_aliases(self) -> None:
        """Test backward compatibility aliases."""
        assert FlextAuthConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert FlextAuthConstants.TOKEN_TYPE_ACCESS == "access"

    def test_flext_core_integration_standalone(self) -> None:
        """Test flext-core integration works in standalone mode."""
        # Test password length constants from flext-core integration
        assert FlextAuthConstants.MIN_PASSWORD_LENGTH >= 8
        assert FlextAuthConstants.MAX_PASSWORD_LENGTH >= 32
        assert isinstance(FlextAuthConstants.MIN_PASSWORD_LENGTH, int)
        assert isinstance(FlextAuthConstants.MAX_PASSWORD_LENGTH, int)

    def test_type_annotations_exist(self) -> None:
        """Test that ClassVar annotations work correctly."""
        assert hasattr(FlextAuthConstants, "__annotations__")

        # Verify constants have correct types
        assert isinstance(FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS, int)
        assert isinstance(FlextAuthConstants.TOKEN_TYPE_ACCESS, str)
        assert isinstance(FlextAuthConstants.ROLE_ADMIN, str)

    @pytest.mark.unit
    def test_all_constant_categories_present(self) -> None:
        """Test that all constant categories are present."""
        # Token types
        assert hasattr(FlextAuthConstants, "TokenTypes")
        assert hasattr(FlextAuthConstants.TokenTypes, "ACCESS")
        assert hasattr(FlextAuthConstants.TokenTypes, "REFRESH")

        # User roles
        assert hasattr(FlextAuthConstants, "UserRoles")
        assert hasattr(FlextAuthConstants.UserRoles, "ADMIN")
        assert hasattr(FlextAuthConstants.UserRoles, "USER")

        # Security settings
        assert hasattr(FlextAuthConstants, "Security")
        assert hasattr(FlextAuthConstants.Security, "DEFAULT_MAX_LOGIN_ATTEMPTS")

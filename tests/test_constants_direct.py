"""Unit tests for FlextAuthConstants - Consolidated from legacy test file.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth.constants import FlextAuthConstants


class TestFlextAuthConstantsDirect:
    """Unit tests for FlextAuthConstants direct access patterns."""

    def test_direct_constant_access(self) -> None:
        """Test direct access to constants."""
        assert FlextAuthConstants.DEFAULT_MAX_LOGIN_ATTEMPTS == 5
        assert FlextAuthConstants.TOKEN_TYPE_ACCESS == "access"
        assert FlextAuthConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"

    def test_nested_class_access_backward_compatibility(self) -> None:
        """Test nested class access for backward compatibility."""
        assert FlextAuthConstants.TokenTypes.ACCESS == "access"
        assert FlextAuthConstants.TokenTypes.REFRESH == "refresh"
        assert FlextAuthConstants.UserRoles.ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert FlextAuthConstants.Security.DEFAULT_MAX_LOGIN_ATTEMPTS == 5

    def test_semantic_constants_backward_compatibility(self) -> None:
        """Test backward compatibility aliases."""
        # Test that constants are available directly
        assert FlextAuthConstants.ROLE_ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert FlextAuthConstants.TOKEN_TYPE_ACCESS == "access"

    def test_flext_core_integration_constants(self) -> None:
        """Test flext-core integration constants."""
        assert FlextAuthConstants.MIN_PASSWORD_LENGTH >= 8
        assert FlextAuthConstants.MAX_PASSWORD_LENGTH >= 32
        assert isinstance(FlextAuthConstants.MIN_PASSWORD_LENGTH, int)
        assert isinstance(FlextAuthConstants.MAX_PASSWORD_LENGTH, int)

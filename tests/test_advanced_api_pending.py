"""Placeholder for advanced API functionality tests.

Many advanced API functions are not yet implemented. This is a temporary
placeholder to prevent import errors while development continues.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

import pytest

from flext_auth import (
    FLEXT_AUTH_ADMIN,
    FLEXT_AUTH_GUEST,
    FLEXT_AUTH_USER,
    FlextAuthMixin,
    FlextAuthSessionMixin,
    FlextAuthUserMixin,
    flext_auth_generate_jwt,
    flext_auth_permission_required,
    flext_auth_role_required,
)


@pytest.mark.skip(reason="Advanced API functions not fully implemented yet")
class TestAdvancedAPI:
    """Test placeholder for advanced API functionality - PENDING IMPLEMENTATION."""

    def test_legacy_types_available(self) -> None:
        """Test that legacy type aliases are available."""
        # Test role constants
        assert FLEXT_AUTH_ADMIN is not None
        assert FLEXT_AUTH_USER is not None
        assert FLEXT_AUTH_GUEST is not None

        # Test type aliases (these are just type definitions)
        # FlextAuthClaims, FlextAuthHeaders, etc. should be importable

        # Test mixin classes
        assert FlextAuthMixin is not None
        assert FlextAuthUserMixin is not None
        assert FlextAuthSessionMixin is not None

        # Test decorators
        assert flext_auth_role_required is not None
        assert flext_auth_permission_required is not None

    def test_basic_jwt_functionality(self) -> None:
        """Test basic JWT functionality that exists."""
        # Test JWT generation
        token = flext_auth_generate_jwt({"user_id": "test"})
        assert isinstance(token, str)
        assert len(token) > 0

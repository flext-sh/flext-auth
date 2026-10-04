"""Real-world token flow tests for the flext-auth public API.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import pytest

from flext_auth import FlextAuth
from tests.constants import TestsFlextAuthConstants as c
from tests.utilities import TestsFlextAuthUtilities as u


class TestsFlextAuthTokenRealFlows:
    """Token flow tests using only FlextAuth public API."""

    pytestmark = pytest.mark.usefixtures("reset_auth_singleton")

    @staticmethod
    def test_create_token_for_registered_user() -> None:
        """Test create token for registered user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="token-flow-user",
            email="token-flow-user@example.com",
            password=c.TEST_PASSWORD,
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)
        token_value = token_result.value
        u.Tests.Matchers.that(token_value, is_=str)
        u.Tests.Matchers.that(token_value.count("."), eq=2)

    @staticmethod
    def test_validate_token_after_creation() -> None:
        """Test validate token after creation."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="token-validate-user",
            email="token-validate-user@example.com",
            password=c.TEST_PASSWORD,
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)

        validation_result = auth.token_service.validate_token(token_result.value)
        u.Tests.Matchers.that(validation_result.success, eq=True)

    @staticmethod
    def test_validate_token_rejects_invalid_token() -> None:
        """Test validate token rejects invalid token."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        invalid_result = auth.token_service.validate_token("invalid.jwt.token")
        u.Tests.Matchers.that(invalid_result.success, eq=False)

    @staticmethod
    def test_authenticate_user_and_create_token_sequence() -> None:
        """Test authenticate user and create token sequence."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        username = "sequence-user"
        password = c.TEST_PASSWORD
        register_result = auth.register_user(
            username=username, email="sequence-user@example.com", password=password,
        )
        u.Tests.Matchers.ok(register_result)

        authenticated = auth.authenticate_user(username, password)
        u.Tests.Matchers.ok(authenticated)

        token_result = auth.create_token(identity_id=authenticated.value.unique_id)
        u.Tests.Matchers.ok(token_result)

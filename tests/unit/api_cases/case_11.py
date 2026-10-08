"""FlextAuth API test case group 11.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import threading
from threading import Thread

from flext_auth import FlextAuth
from tests import TestsFlextAuthUtilities, c
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase11:
    """FlextAuth API case group 11."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_flext_auth_concurrent_operations() -> None:
        """Test auth concurrent operations."""
        auth = FlextAuth()

        def register_user(index: int) -> None:
            _ = auth.register_user(
                username=f"user_{index}",
                email=f"user_{index}@example.com",
                password=c.TEST_CREDENTIAL,
            )

        def authenticate_user(index: int) -> None:
            _ = auth.authenticate_user(f"user_{index}", c.TEST_CREDENTIAL)

        threads: list[Thread] = []
        for i in range(5):
            thread = threading.Thread(target=register_user, args=(i,))
            threads.append(thread)
            thread.start()
        for thread in threads:
            thread.join()
        auth_threads: list[Thread] = []
        for i in range(5):
            thread = threading.Thread(target=authenticate_user, args=(i,))
            auth_threads.append(thread)
            thread.start()
        for thread in auth_threads:
            thread.join()

    @staticmethod
    def test_public_api_create_token_for_registered_user() -> None:
        """Test public api create token for registered user."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="public-api-token-user",
            email="public-api-token-user@example.com",
            password=c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.ok(token_result)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.value.count("."), eq=2)

    @staticmethod
    def test_public_api_validate_token_success() -> None:
        """Test public api validate token success."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="public-api-validate-user",
            email="public-api-validate-user@example.com",
            password=c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.ok(token_result)

        validation_result = auth.session_service.validate_token(token_result.value)
        TestsFlextAuthUtilities.Tests.Matchers.ok(validation_result)
        TestsFlextAuthUtilities.Tests.Matchers.that(validation_result.value, eq=True)

    @staticmethod
    def test_public_api_validate_token_failure() -> None:
        """Test public api validate token failure."""
        auth = FlextAuth.quick_start(create_admin_user=False)
        validation_result = auth.session_service.validate_token("invalid.jwt.token")
        TestsFlextAuthUtilities.Tests.Matchers.fail(validation_result)

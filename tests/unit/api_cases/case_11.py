"""FlextAuth API test case group 11."""

from __future__ import annotations

import threading
from threading import Thread

from flext_auth import FlextAuth
from tests import c, u
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper


class TestsFlextAuthApiCase11:
    """FlextAuth API case group 11."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_flext_auth_concurrent_operations(self) -> None:
        """Test auth concurrent operations."""
        auth = FlextAuth()

        def register_user(index: int) -> None:
            _ = auth.register_user(
                username=f"user_{index}",
                email=f"user_{index}@example.com",
                password=c.TEST_PASSWORD,
            )

        def authenticate_user(index: int) -> None:
            _ = auth.authenticate_user(f"user_{index}", c.TEST_PASSWORD)

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

    def test_public_api_create_token_for_registered_user(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="public-api-token-user",
            email="public-api-token-user@example.com",
            password=c.TEST_PASSWORD,
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)
        u.Tests.Matchers.that(token_result.value.count("."), eq=2)

    def test_public_api_validate_token_success(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="public-api-validate-user",
            email="public-api-validate-user@example.com",
            password=c.TEST_PASSWORD,
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)

        validation_result = auth.token_service.validate_token(token_result.value)
        u.Tests.Matchers.ok(validation_result)
        u.Tests.Matchers.that(validation_result.value, eq=True)

    def test_public_api_validate_token_failure(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        validation_result = auth.token_service.validate_token("invalid.jwt.token")
        u.Tests.Matchers.fail(validation_result)


__all__: list[str] = ["TestsFlextAuthApiCase11"]

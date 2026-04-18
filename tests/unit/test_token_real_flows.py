from __future__ import annotations

from flext_auth import FlextAuth, p
from tests import u


class TestTokenRealFlows:
    """Token flow tests using only FlextAuth public API."""

    def test_create_token_for_registered_user(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="token-flow-user",
            email="token-flow-user@example.com",
            password="TokenFlowPass123!",
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)
        token_value = token_result.value
        u.Tests.Matchers.that(token_value, is_=str)
        u.Tests.Matchers.that(token_value.count("."), eq=2)

    def test_validate_token_after_creation(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        registered = auth.register_user(
            username="token-validate-user",
            email="token-validate-user@example.com",
            password="TokenValidatePass123!",
        )
        u.Tests.Matchers.ok(registered)

        token_result = auth.create_token(identity_id=registered.value.unique_id)
        u.Tests.Matchers.ok(token_result)

        validation_result = auth.validate_token(token_result.value)
        u.Tests.Matchers.ok(validation_result)
        u.Tests.Matchers.that(validation_result.value, eq=True)

    def test_validate_token_rejects_invalid_token(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        invalid_result = auth.validate_token("invalid.jwt.token")
        u.Tests.Matchers.fail(invalid_result)

    def test_authenticate_user_and_create_token_sequence(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        username = "sequence-user"
        password = "SequencePass123!"
        register_result = auth.register_user(
            username=username,
            email="sequence-user@example.com",
            password=password,
        )
        u.Tests.Matchers.ok(register_result)

        authenticated = auth.authenticate_user(username, password)
        u.Tests.Matchers.ok(authenticated)

        token_result = auth.create_token(identity_id=authenticated.value.unique_id)
        u.Tests.Matchers.ok(token_result)

    def test_execute_returns_failure_for_generic_call(self) -> None:
        auth = FlextAuth.quick_start(create_admin_user=False)
        execute_result: p.Result[bool] = auth.execute()
        u.Tests.Matchers.fail(execute_result)

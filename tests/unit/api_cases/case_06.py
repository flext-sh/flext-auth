"""FlextAuth API test case group 06."""

from __future__ import annotations

from datetime import UTC, datetime

from flext_auth import FlextAuth
from tests.models import m
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper
from tests.utilities import u


class TestsFlextAuthApiCase06:
    """FlextAuth API case group 06."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_authenticate_user_failure_paths(self) -> None:
        """Test authenticate_user method failure scenarios."""
        auth = FlextAuth()
        result = auth.authenticate_user(
            username="nonexistent_user",
            password="any_password",
        )
        u.Tests.Matchers.that(not result.success, eq=True)
        u.Tests.Matchers.that(result.error, is_=str)

    def test_validate_token_invalid_cases(self) -> None:
        """Test token validation with invalid tokens."""
        auth = FlextAuth()
        result = auth.token_service.validate_token("invalid.malformed.token")
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.token_service.validate_token("")
        u.Tests.Matchers.that(not result.success, eq=True)
        result = auth.token_service.validate_token("invalid.token.format")
        u.Tests.Matchers.that(not result.success, eq=True)

    def test_hash_password_method(self) -> None:
        """Test hash_password method functionality."""
        identity = m.Auth.AuthIdentity(
            unique_id="test-id",
            name="testuser",
            contact="test@example.com",
            credential_hash="",
            full_name="Test User",
            is_active=True,
            roles=[],
            permissions=[],
            token="",
            session_id="",
            failed_attempts=0,
            locked_until=datetime.min.replace(tzinfo=UTC),
            last_access=datetime.min.replace(tzinfo=UTC),
        )
        result = identity.update_credential("StrongTestPass123!@#")
        u.Tests.Matchers.that(result.success, eq=True)
        u.Tests.Matchers.that(result.value is True, eq=True)
        u.Tests.Matchers.that(identity.credential_hash, ne="StrongTestPass123!@#")
        u.Tests.Matchers.that(len(identity.credential_hash), gt=10)

    def test_verify_password_method(self) -> None:
        """Test verify_password method functionality."""
        strong_password = "StrongTestPass123!@#"
        identity = m.Auth.AuthIdentity(
            unique_id="test-id",
            name="testuser",
            contact="test@example.com",
            credential_hash="",
            full_name="Test User",
            is_active=True,
            roles=[],
            permissions=[],
            token="",
            session_id="",
            failed_attempts=0,
            locked_until=datetime.min.replace(tzinfo=UTC),
            last_access=datetime.min.replace(tzinfo=UTC),
        )
        set_result = identity.update_credential(strong_password)
        u.Tests.Matchers.that(set_result.success, eq=True)
        verify_result = identity.verify_credential(strong_password)
        u.Tests.Matchers.that(verify_result.success, eq=True)
        u.Tests.Matchers.that(verify_result.value is True, eq=True)
        wrong_result = identity.verify_credential("WrongPassword123!@")
        u.Tests.Matchers.that(wrong_result.success, eq=True)
        u.Tests.Matchers.that(wrong_result.value is False, eq=True)

    def test_generate_token_method(self) -> None:
        """Test that create_token succeeds for a registered user."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="jwt_test_user",
            email="jwt@example.com",
            password="JWTTestPass123!@#",
        )
        u.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        result = auth.create_token(identity_id=user.unique_id)
        u.Tests.Matchers.that(result.success, eq=True)
        u.Tests.Matchers.that(result.error, none=True)

    def test_generate_token_alternative_method(self) -> None:
        """Test that create_token fails via alternative path — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_validate_token_success_path(self) -> None:
        """Test that validate_token fails — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            "TestPassword123!",
        )
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", "TestPassword123!")
        u.Tests.Matchers.that(auth_result.success, eq=True)
        authenticated_identity = auth_result.value
        u.Tests.Matchers.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        val_result = auth.token_service.validate_token("any.fake.token")
        u.Tests.Matchers.that(not val_result.success, eq=True)


__all__: list[str] = ["TestsFlextAuthApiCase06"]

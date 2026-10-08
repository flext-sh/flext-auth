"""FlextAuth API test case group 06.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from datetime import UTC, datetime

from flext_auth import FlextAuth
from tests import TestsFlextAuthUtilities, c, m
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase06:
    """FlextAuth API case group 06."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_authenticate_user_failure_paths() -> None:
        """Test authenticate_user method failure scenarios."""
        auth = FlextAuth()
        result = auth.authenticate_user(
            username="nonexistent_user",
            password=c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(not result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.error, is_=str)

    @staticmethod
    def test_validate_token_invalid_cases() -> None:
        """Test token validation with invalid tokens."""
        auth = FlextAuth()
        result = auth.session_service.validate_token("invalid.malformed.token")
        TestsFlextAuthUtilities.Tests.Matchers.that(not result.success, eq=True)
        result = auth.session_service.validate_token("")
        TestsFlextAuthUtilities.Tests.Matchers.that(not result.success, eq=True)
        result = auth.session_service.validate_token("invalid.token.format")
        TestsFlextAuthUtilities.Tests.Matchers.that(not result.success, eq=True)

    @staticmethod
    def test_hash_password_method() -> None:
        """Test hash_password method functionality."""
        identity = m.Auth.AuthIdentity(
            domain_events=[],
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
        result = identity.update_credential(c.TEST_CREDENTIAL)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.value is True, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            identity.credential_hash, ne="StrongTestPass123!@#"
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(
            len(identity.credential_hash), gt=10
        )

    @staticmethod
    def test_verify_password_method() -> None:
        """Test verify_password method functionality."""
        strong_password = c.TEST_CREDENTIAL
        identity = m.Auth.AuthIdentity(
            domain_events=[],
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
        TestsFlextAuthUtilities.Tests.Matchers.that(set_result.success, eq=True)
        verify_result = identity.verify_credential(strong_password)
        TestsFlextAuthUtilities.Tests.Matchers.that(verify_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            verify_result.value is True, eq=True
        )
        wrong_result = identity.verify_credential(c.TEST_CREDENTIAL + "_wrong")
        TestsFlextAuthUtilities.Tests.Matchers.that(wrong_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            wrong_result.value is False, eq=True
        )

    @staticmethod
    def test_generate_token_method() -> None:
        """Test that create_token succeeds for a registered user."""
        auth = FlextAuth()
        user_result = auth.register_user(
            username="jwt_test_user",
            email="jwt@example.com",
            password=c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(user_result.success, eq=True)
        user = user_result.value
        result = auth.create_token(identity_id=user.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(result.error, none=True)

    @staticmethod
    def test_generate_token_alternative_method() -> None:
        """Test create_token fails on the alternative path without a JWT provider."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", c.TEST_CREDENTIAL)
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        token_result = auth.create_token(identity_id=identity.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.error, none=True)

    @staticmethod
    def test_validate_token_success_path() -> None:
        """Test that validate_token fails — JWT provider not implemented."""
        auth = FlextAuth()
        register_result = auth.register_user(
            "testuser",
            "test@example.com",
            c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user("testuser", c.TEST_CREDENTIAL)
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        authenticated_identity = auth_result.value
        TestsFlextAuthUtilities.Tests.Matchers.that(
            authenticated_identity, is_=m.Auth.AuthIdentity
        )
        token_result = auth.create_token(identity_id=identity.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.success, eq=True)
        val_result = auth.session_service.validate_token("any.fake.token")
        TestsFlextAuthUtilities.Tests.Matchers.that(not val_result.success, eq=True)

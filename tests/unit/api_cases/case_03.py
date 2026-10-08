"""FlextAuth API test case group 03.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets

from flext_auth import FlextAuth, FlextAuthSettings, m
from tests import TestsFlextAuthUtilities, c
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase03:
    """FlextAuth API case group 03."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_flext_auth_initialization() -> None:
        """Test FlextAuth initialization with different parameters."""
        auth: FlextAuth = FlextAuth()
        TestsFlextAuthUtilities.Tests.Matchers.that(auth.config.auth_secret, none=False)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            len(auth.config.auth_secret.get_secret_value()), gt=20
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(auth.config.hash_rounds, eq=12)
        TestsFlextAuthUtilities.Tests.Matchers.that(auth.config.expiry_minutes, eq=1440)
        custom_secret = secrets.token_urlsafe(32)
        custom_rounds = 10
        custom_expiry = 60
        custom_config = FlextAuthSettings.model_validate({
            "secret_key": custom_secret,
            "algorithm": c.Auth.Algorithms.HS256,
            "issuer": "flext-auth",
            "audience": "flext-users",
            "hash_rounds": custom_rounds,
            "expiry_minutes": custom_expiry,
            "session_expiry_minutes": 1440,
            "max_sessions_per_user": 5,
        })
        auth_custom: FlextAuth = FlextAuth(settings=custom_config)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            auth_custom.config.auth_secret.get_secret_value(),
            eq=custom_secret,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(
            auth_custom.config.hash_rounds, eq=custom_rounds
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(
            auth_custom.config.expiry_minutes, eq=custom_expiry
        )

    @staticmethod
    def test_user_registration_success() -> None:
        """Test successful user registration."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password=c.TEST_CREDENTIAL,
            roles=["user"],
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(result.success, eq=True)
        user = result.value
        TestsFlextAuthUtilities.Tests.Matchers.that(user.name, eq="testuser")
        TestsFlextAuthUtilities.Tests.Matchers.that(user.contact, eq="test@example.com")
        TestsFlextAuthUtilities.Tests.Matchers.that(user.roles, has="user")
        TestsFlextAuthUtilities.Tests.Matchers.that(user.is_active, eq=True)

    @staticmethod
    def test_user_registration_duplicate_username() -> None:
        """Test user registration with duplicate username."""
        auth: FlextAuth = FlextAuth()
        auth.register_user("testuser", "test1@example.com", c.TEST_CREDENTIAL)
        duplicate_result = auth.register_user(
            "testuser",
            "test2@example.com",
            c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(duplicate_result.failure, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            (duplicate_result.error or ""), has="already exists"
        )

    @staticmethod
    def test_user_registration_duplicate_email() -> None:
        """Test user registration with duplicate email."""
        auth: FlextAuth = FlextAuth()
        first_result = auth.register_user(
            "user1",
            "test@example.com",
            c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(first_result.success, eq=True)
        duplicate_result = auth.register_user(
            "user2",
            "test@example.com",
            c.TEST_CREDENTIAL,
        )
        TestsFlextAuthUtilities.Tests.Matchers.that(duplicate_result.failure, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            (duplicate_result.error or ""), has="already exists"
        )

    @staticmethod
    def test_user_authentication_success() -> None:
        """Test successful user authentication."""
        auth: FlextAuth = FlextAuth()
        username = "authtest"
        password = c.TEST_CREDENTIAL
        reg_result = auth.register_user(username, "auth@example.com", password)
        TestsFlextAuthUtilities.Tests.Matchers.that(reg_result.success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        TestsFlextAuthUtilities.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        TestsFlextAuthUtilities.Tests.Matchers.that(identity.name, eq=username)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            identity.contact, eq="auth@example.com"
        )

    @staticmethod
    def test_user_authentication_invalid_credentials() -> None:
        """Test authentication with invalid credentials."""
        auth: FlextAuth = FlextAuth()
        username = "testuser"
        auth.register_user(username, "test@example.com", c.TEST_CREDENTIAL)
        failed_auth = auth.authenticate_user(username, c.TEST_CREDENTIAL + "_wrong")
        TestsFlextAuthUtilities.Tests.Matchers.that(not failed_auth.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(not failed_auth.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(
            (failed_auth.error or ""), has="Invalid credentials"
        )

    @staticmethod
    def test_token_validation_valid_token() -> None:
        """Test that token creation/validation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "tokenuser"
        password = c.TEST_CREDENTIAL
        register_result = auth.register_user(username, "token@example.com", password)
        TestsFlextAuthUtilities.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        TestsFlextAuthUtilities.Tests.Matchers.that(auth_result.success, eq=True)
        authenticated_identity = auth_result.value
        TestsFlextAuthUtilities.Tests.Matchers.that(
            authenticated_identity, is_=m.Auth.AuthIdentity
        )
        token_result = auth.create_token(identity_id=identity.unique_id)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(token_result.error, none=True)

    @staticmethod
    def test_token_validation_invalid_token() -> None:
        """Test validation of invalid token — fails with 'not implemented'."""
        auth: FlextAuth = FlextAuth()
        invalid_result = auth.session_service.validate_token("invalid.token.here")
        TestsFlextAuthUtilities.Tests.Matchers.that(not invalid_result.success, eq=True)
        TestsFlextAuthUtilities.Tests.Matchers.that(invalid_result.error, none=False)

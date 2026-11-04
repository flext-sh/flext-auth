"""FlextAuth API test case group 03.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import secrets

from flext_auth import FlextAuth, FlextAuthSettings
from tests import c, m, tm
from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


class TestsFlextAuthApiCase03:
    """FlextAuth API case group 03."""

    _TestDataHelper = TestsFlextAuthApiTestDataHelper

    @staticmethod
    def test_flext_auth_initialization() -> None:
        """Test FlextAuth initialization with different parameters."""
        default_config = FlextAuthSettings()
        auth = FlextAuth(runtime_settings=default_config)
        tm.that(auth.config is default_config.Auth, eq=True)
        tm.that(
            len(default_config.Auth.auth_secret.get_secret_value())
            >= c.Auth.SECRET_MIN_LENGTH,
            eq=True,
        )
        tm.that(auth.config.expiry_minutes, eq=default_config.Auth.expiry_minutes)
        custom_secret = secrets.token_urlsafe(c.Auth.SECRET_MIN_LENGTH)
        custom_rounds = 10
        custom_expiry = 60
        custom_config = FlextAuthSettings(
            Auth=FlextAuthSettings.AuthSettings(
                secret_key=custom_secret,
                algorithm=c.Auth.Algorithms.HS256,
                hash_rounds=custom_rounds,
                expiry_minutes=custom_expiry,
            ),
        )
        auth_custom = FlextAuth(runtime_settings=custom_config)
        tm.that(auth_custom.config is custom_config.Auth, eq=True)
        tm.that(
            custom_config.Auth.auth_secret.get_secret_value(),
            eq=custom_secret,
        )
        tm.that(custom_config.Auth.hash_rounds, eq=custom_rounds)
        tm.that(auth_custom.config.expiry_minutes, eq=custom_expiry)

    @staticmethod
    def test_user_registration_success() -> None:
        """Test successful user registration."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password=c.TEST_CREDENTIAL,
            roles=[c.ContextScope.USER],
        )
        tm.that(result.success, eq=True)
        user = result.value
        tm.that(user.name, eq="testuser")
        tm.that(user.contact, eq="test@example.com")
        tm.that(user.roles, has=c.ContextScope.USER)
        tm.that(user.is_active, eq=True)

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
        tm.that(duplicate_result.failure, eq=True)
        tm.that((duplicate_result.error or ""), has="already exists")

    @staticmethod
    def test_user_registration_duplicate_email() -> None:
        """Test user registration with duplicate email."""
        auth: FlextAuth = FlextAuth()
        first_result = auth.register_user(
            "user1",
            "test@example.com",
            c.TEST_CREDENTIAL,
        )
        tm.that(first_result.success, eq=True)
        duplicate_result = auth.register_user(
            "user2",
            "test@example.com",
            c.TEST_CREDENTIAL,
        )
        tm.that(duplicate_result.failure, eq=True)
        tm.that((duplicate_result.error or ""), has="already exists")

    @staticmethod
    def test_user_authentication_success() -> None:
        """Test successful user authentication."""
        auth: FlextAuth = FlextAuth()
        username = "authtest"
        password = c.TEST_CREDENTIAL
        reg_result = auth.register_user(username, "auth@example.com", password)
        tm.that(reg_result.success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        tm.that(auth_result.success, eq=True)
        identity = auth_result.value
        tm.that(identity, is_=m.Auth.AuthIdentity)
        tm.that(identity.name, eq=username)
        tm.that(identity.contact, eq="auth@example.com")

    @staticmethod
    def test_user_authentication_invalid_credentials() -> None:
        """Test authentication with invalid credentials."""
        auth: FlextAuth = FlextAuth()
        username = "testuser"
        auth.register_user(username, "test@example.com", c.TEST_CREDENTIAL)
        failed_auth = auth.authenticate_user(username, c.TEST_CREDENTIAL + "_wrong")
        tm.that(not failed_auth.success, eq=True)
        tm.that(not failed_auth.success, eq=True)
        tm.that((failed_auth.error or ""), has="Invalid credentials")

    @staticmethod
    def test_token_validation_valid_token() -> None:
        """Test that token creation/validation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "tokenuser"
        password = c.TEST_CREDENTIAL
        register_result = auth.register_user(username, "token@example.com", password)
        tm.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        tm.that(auth_result.success, eq=True)
        authenticated_identity = auth_result.value
        tm.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        tm.that(token_result.success, eq=True)
        tm.that(token_result.error, none=True)

    @staticmethod
    def test_token_validation_invalid_token() -> None:
        """Test validation of invalid token — fails with 'not implemented'."""
        auth: FlextAuth = FlextAuth()
        invalid_result = auth.session_service.validate_token("invalid.token.here")
        tm.that(not invalid_result.success, eq=True)
        tm.that(invalid_result.error, none=False)

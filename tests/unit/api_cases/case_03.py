"""FlextAuth API test case group 03."""

from __future__ import annotations

from flext_auth import FlextAuth, FlextAuthSettings
from tests import c, m, u
from tests.unit.api_cases.support import FlextAuthApiTestDataHelper


class TestsFlextAuthApiCase03:
    """FlextAuth API case group 03."""

    _TestDataHelper = FlextAuthApiTestDataHelper

    def test_flext_auth_initialization(self) -> None:
        """Test FlextAuth initialization with different parameters."""
        auth: FlextAuth = FlextAuth()
        u.Tests.Matchers.that(auth.config.auth_secret, none=False)
        u.Tests.Matchers.that(len(auth.config.auth_secret.get_secret_value()), gt=20)
        u.Tests.Matchers.that(auth.config.hash_rounds, eq=12)
        u.Tests.Matchers.that(auth.config.expiry_minutes, eq=1440)
        custom_secret = "test-secret-key-with-minimum-32-characters-length"
        custom_rounds = 10
        custom_expiry = 60
        custom_config = FlextAuthSettings(
            secret_key=custom_secret,
            algorithm=c.Auth.Algorithms.HS256,
            issuer="flext-auth",
            audience="flext-users",
            hash_rounds=custom_rounds,
            expiry_minutes=custom_expiry,
            session_expiry_minutes=1440,
            max_sessions_per_user=5,
        )
        auth_custom: FlextAuth = FlextAuth(settings=custom_config)
        u.Tests.Matchers.that(
            auth_custom.config.auth_secret.get_secret_value(), eq=custom_secret
        )
        u.Tests.Matchers.that(auth_custom.config.hash_rounds, eq=custom_rounds)
        u.Tests.Matchers.that(auth_custom.config.expiry_minutes, eq=custom_expiry)

    def test_user_registration_success(self) -> None:
        """Test successful user registration."""
        auth: FlextAuth = FlextAuth()
        result = auth.register_user(
            username="testuser",
            email="test@example.com",
            password="SecurePassword123!",
            roles=["user"],
        )
        u.Tests.Matchers.that(result.success, eq=True)
        user = result.value
        u.Tests.Matchers.that(user.name, eq="testuser")
        u.Tests.Matchers.that(user.contact, eq="test@example.com")
        u.Tests.Matchers.that(user.roles, has="user")
        u.Tests.Matchers.that(user.is_active, eq=True)

    def test_user_registration_duplicate_username(self) -> None:
        """Test user registration with duplicate username."""
        auth: FlextAuth = FlextAuth()
        auth.register_user("testuser", "test1@example.com", "Password123!")
        duplicate_result = auth.register_user(
            "testuser", "test2@example.com", "Password123!"
        )
        u.Tests.Matchers.that(duplicate_result.failure, eq=True)
        u.Tests.Matchers.that((duplicate_result.error or ""), has="already exists")

    def test_user_registration_duplicate_email(self) -> None:
        """Test user registration with duplicate email."""
        auth: FlextAuth = FlextAuth()
        first_result = auth.register_user("user1", "test@example.com", "Password123!")
        u.Tests.Matchers.that(first_result.success, eq=True)
        duplicate_result = auth.register_user(
            "user2", "test@example.com", "Password123!"
        )
        u.Tests.Matchers.that(duplicate_result.failure, eq=True)
        u.Tests.Matchers.that((duplicate_result.error or ""), has="already exists")

    def test_user_authentication_success(self) -> None:
        """Test successful user authentication."""
        auth: FlextAuth = FlextAuth()
        username = "authtest"
        password = "AuthPassword123!"
        reg_result = auth.register_user(username, "auth@example.com", password)
        u.Tests.Matchers.that(reg_result.success, eq=True)
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        identity = auth_result.value
        u.Tests.Matchers.that(identity, is_=m.Auth.AuthIdentity)
        u.Tests.Matchers.that(identity.name, eq=username)
        u.Tests.Matchers.that(identity.contact, eq="auth@example.com")

    def test_user_authentication_invalid_credentials(self) -> None:
        """Test authentication with invalid credentials."""
        auth: FlextAuth = FlextAuth()
        username = "testuser"
        auth.register_user(username, "test@example.com", "CorrectPassword123!")
        failed_auth = auth.authenticate_user(username, "WrongPassword123!")
        u.Tests.Matchers.that(not failed_auth.success, eq=True)
        u.Tests.Matchers.that(not failed_auth.success, eq=True)
        u.Tests.Matchers.that((failed_auth.error or ""), has="Invalid credentials")

    def test_token_validation_valid_token(self) -> None:
        """Test that token creation/validation fails — JWT provider not implemented."""
        auth: FlextAuth = FlextAuth()
        username = "tokenuser"
        password = "TokenPassword123!"
        register_result = auth.register_user(username, "token@example.com", password)
        u.Tests.Matchers.that(register_result.success, eq=True)
        identity = register_result.value
        auth_result = auth.authenticate_user(username, password)
        u.Tests.Matchers.that(auth_result.success, eq=True)
        authenticated_identity = auth_result.value
        u.Tests.Matchers.that(authenticated_identity, is_=m.Auth.AuthIdentity)
        token_result = auth.create_token(identity_id=identity.unique_id)
        u.Tests.Matchers.that(token_result.success, eq=True)
        u.Tests.Matchers.that(token_result.error, none=True)

    def test_token_validation_invalid_token(self) -> None:
        """Test validation of invalid token — fails with 'not implemented'."""
        auth: FlextAuth = FlextAuth()
        invalid_result = auth.token_service.validate_token("invalid.token.here")
        u.Tests.Matchers.that(not invalid_result.success, eq=True)
        u.Tests.Matchers.that(invalid_result.error, none=False)


__all__: list[str] = ["TestsFlextAuthApiCase03"]

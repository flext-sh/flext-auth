"""Test coverage for FlextAuthUtilities to improve overall coverage."""

from datetime import UTC, datetime, timedelta

from pydantic import SecretStr

from flext_auth import FlextAuthModels, FlextAuthUtilities


class TestFlextAuthUtilitiesCoverage:
    """Test coverage for FlextAuthUtilities methods."""

    async def test_execute_async(self) -> None:
        """Test async execute method."""
        utilities = FlextAuthUtilities()
        result = await utilities.execute_async()

        assert result.is_success
        assert result.value["status"] == "operational"
        assert result.value["service"] == "flext-auth-utilities"
        assert "timestamp" in result.value

    def test_token_validation_expired_token(self) -> None:
        """Test token validation with expired token."""
        # Create an expired JWT token
        {
            "user_id": "test_user",
            "exp": int((datetime.now(UTC) - timedelta(hours=1)).timestamp()),
        }

        result = FlextAuthUtilities.TokenValidation.validate_jwt_token(
            "expired_token", SecretStr("test_secret")
        )

        assert result.is_failure
        assert result.error is not None
        assert "invalid" in result.error.lower()

    def test_token_validation_invalid_token(self) -> None:
        """Test token validation with invalid token."""
        result = FlextAuthUtilities.TokenValidation.validate_jwt_token(
            "invalid_token", SecretStr("test_secret")
        )

        assert result.is_failure
        assert result.error is not None
        assert "invalid" in result.error.lower()

    def test_bearer_token_validation_invalid_format(self) -> None:
        """Test bearer token validation with invalid format."""
        result = FlextAuthUtilities.TokenValidation.validate_bearer_token(
            "InvalidFormat token123"
        )

        assert result.is_failure
        assert result.error is not None
        assert "authorization" in result.error.lower()

    def test_bearer_token_validation_empty_header(self) -> None:
        """Test bearer token validation with empty header."""
        result = FlextAuthUtilities.TokenValidation.validate_bearer_token("")

        assert result.is_failure
        assert result.error is not None
        assert "required" in result.error.lower()

    def test_api_key_validation_empty_key(self) -> None:
        """Test API key validation with empty key."""
        result = FlextAuthUtilities.TokenValidation.validate_api_key(
            "", {"valid_key1", "valid_key2"}
        )

        assert result.is_failure
        assert result.error is not None
        assert "required" in result.error.lower()

    def test_session_validation_valid_session(self) -> None:
        """Test session validation with valid session."""
        session_store = {}
        session = FlextAuthModels.Session(
            session_id="test_session_id",
            session_token="test_token_that_is_long_enough_for_validation_32_chars",
            user_id="test_user",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            is_active=True,
            ip_address=None,
            user_agent=None,
        )
        session_store["test_token_that_is_long_enough_for_validation_32_chars"] = (
            session
        )

        result = FlextAuthUtilities.TokenValidation.validate_session_token(
            "test_token_that_is_long_enough_for_validation_32_chars", session_store
        )

        assert result.is_success
        assert result.value == session

    def test_session_validation_expired_session(self) -> None:
        """Test session validation with expired session."""
        session_store = {}
        session = FlextAuthModels.Session(
            session_id="expired_session_id",
            session_token="expired_token_that_is_long_enough_for_validation_32_chars",
            user_id="test_user",
            expires_at=datetime.now(UTC) - timedelta(hours=1),  # Expired
            is_active=True,
            ip_address=None,
            user_agent=None,
        )
        session_store["expired_token_that_is_long_enough_for_validation_32_chars"] = (
            session
        )

        result = FlextAuthUtilities.TokenValidation.validate_session_token(
            "expired_token_that_is_long_enough_for_validation_32_chars", session_store
        )

        assert result.is_failure
        assert result.error is not None
        assert "session has expired" in result.error.lower()

    def test_session_validation_invalid_token(self) -> None:
        """Test session validation with invalid token."""
        session_store = {}

        result = FlextAuthUtilities.TokenValidation.validate_session_token(
            "invalid_token", session_store
        )

        assert result.is_failure
        assert result.error is not None
        assert "invalid" in result.error.lower()

    def test_jwt_creation_success(self) -> None:
        """Test JWT token creation."""
        payload = {"user_id": "test_user", "role": "REDACTED_LDAP_BIND_PASSWORD"}
        secret_key = SecretStr("test_secret_key_minimum_32_characters_long")

        result = FlextAuthUtilities.JWTProcessing.create_jwt_token(
            payload, secret_key, 3600
        )

        assert result.is_success
        assert isinstance(result.value, str)

    def test_jwt_creation_invalid_payload(self) -> None:
        """Test JWT token creation with invalid payload."""
        # Empty payload is actually valid for JWT creation
        result = FlextAuthUtilities.JWTProcessing.create_jwt_token(
            {}, SecretStr("test_secret_key_minimum_32_characters_long"), 3600
        )

        assert result.is_success
        assert isinstance(result.value, str)

    def test_jwt_refresh_success(self) -> None:
        """Test JWT token refresh."""
        # First create a token
        payload = {"user_id": "test_user"}
        secret_key = SecretStr("test_secret_key_minimum_32_characters_long")

        create_result = FlextAuthUtilities.JWTProcessing.create_jwt_token(
            payload, secret_key, 3600
        )
        assert create_result.is_success

        # Now refresh it
        refresh_result = FlextAuthUtilities.JWTProcessing.refresh_jwt_token(
            create_result.value, secret_key, 7200
        )

        assert refresh_result.is_success
        assert isinstance(refresh_result.value, str)

    def test_jwt_refresh_invalid_token(self) -> None:
        """Test JWT token refresh with invalid token."""
        secret_key = SecretStr("test_secret_key_minimum_32_characters_long")

        result = FlextAuthUtilities.JWTProcessing.refresh_jwt_token(
            "invalid_token", secret_key, 7200
        )

        assert result.is_failure
        assert result.error is not None
        assert "invalid" in result.error.lower()

    def test_claims_extraction_success(self) -> None:
        """Test JWT claims extraction."""
        payload = {"user_id": "test_user", "role": "REDACTED_LDAP_BIND_PASSWORD"}
        secret_key = SecretStr("test_secret_key_minimum_32_characters_long")

        # Create token first
        create_result = FlextAuthUtilities.JWTProcessing.create_jwt_token(
            payload, secret_key, 3600
        )
        assert create_result.is_success

        # Extract claims
        result = FlextAuthUtilities.JWTProcessing.extract_claims(
            create_result.value, secret_key
        )

        assert result.is_success
        assert result.value["user_id"] == "test_user"
        assert result.value["role"] == "REDACTED_LDAP_BIND_PASSWORD"

    def test_claims_extraction_invalid_token(self) -> None:
        """Test JWT claims extraction with invalid token."""
        secret_key = SecretStr("test_secret_key_minimum_32_characters_long")

        result = FlextAuthUtilities.JWTProcessing.extract_claims(
            "invalid_token", secret_key
        )

        assert result.is_failure
        assert result.error is not None
        assert "invalid" in result.error.lower()

    def test_oauth_state_generation(self) -> None:
        """Test OAuth state parameter generation."""
        result = FlextAuthUtilities.OAuthHelpers.generate_state_parameter()

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_oauth_state_validation_success(self) -> None:
        """Test OAuth state parameter validation success."""
        state = "test_state_123"

        result = FlextAuthUtilities.OAuthHelpers.validate_state_parameter(state, state)

        assert result.is_success
        assert result.value is True

    def test_oauth_state_validation_failure(self) -> None:
        """Test OAuth state parameter validation failure."""
        result = FlextAuthUtilities.OAuthHelpers.validate_state_parameter(
            "state1", "state2"
        )

        assert result.is_success
        assert result.value is False

    def test_oauth_state_validation_empty(self) -> None:
        """Test OAuth state parameter validation with empty values."""
        result = FlextAuthUtilities.OAuthHelpers.validate_state_parameter("", "state2")

        assert result.is_failure
        assert result.error is not None
        assert "empty" in result.error.lower()

    def test_pkce_verifier_generation(self) -> None:
        """Test PKCE verifier generation."""
        result = FlextAuthUtilities.OAuthHelpers.generate_pkce_verifier()

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_pkce_challenge_generation(self) -> None:
        """Test PKCE challenge generation."""
        verifier = "test_verifier_123"

        result = FlextAuthUtilities.OAuthHelpers.generate_pkce_challenge(verifier)

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_password_hashing_success(self) -> None:
        """Test password hashing success."""
        password = SecretStr("test_password_123")

        result = FlextAuthUtilities.PasswordUtilities.hash_password(password)

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_password_verification_success(self) -> None:
        """Test password verification success."""
        password = SecretStr("test_password_123")

        # Hash the password first
        hash_result = FlextAuthUtilities.PasswordUtilities.hash_password(password)
        assert hash_result.is_success

        # Verify it
        verify_result = FlextAuthUtilities.PasswordUtilities.verify_password(
            password, hash_result.value
        )

        assert verify_result.is_success
        assert verify_result.value is True

    def test_password_verification_failure(self) -> None:
        """Test password verification failure."""
        password = SecretStr("test_password_123")
        wrong_password = SecretStr("wrong_password")

        # Hash the password first
        hash_result = FlextAuthUtilities.PasswordUtilities.hash_password(password)
        assert hash_result.is_success

        # Verify with wrong password
        verify_result = FlextAuthUtilities.PasswordUtilities.verify_password(
            wrong_password, hash_result.value
        )

        assert verify_result.is_success
        assert verify_result.value is False

    def test_secure_password_generation_success(self) -> None:
        """Test secure password generation success."""
        result = FlextAuthUtilities.PasswordUtilities.generate_secure_password(16)

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) == 16

    def test_secure_password_generation_too_short(self) -> None:
        """Test secure password generation with too short length."""
        result = FlextAuthUtilities.PasswordUtilities.generate_secure_password(5)

        assert result.is_failure
        assert result.error is not None
        assert "at least" in result.error.lower()

    def test_password_strength_validation_strong(self) -> None:
        """Test password strength validation with strong password."""
        password = SecretStr("StrongPassword123!")

        result = FlextAuthUtilities.PasswordUtilities.validate_password_strength(
            password
        )

        assert result.is_success
        assert result.value["is_strong"] is True
        assert result.value["min_length"] is True
        assert result.value["has_uppercase"] is True
        assert result.value["has_lowercase"] is True
        assert result.value["has_digit"] is True
        assert result.value["has_special"] is True

    def test_password_strength_validation_weak(self) -> None:
        """Test password strength validation with weak password."""
        password = SecretStr("weak")

        result = FlextAuthUtilities.PasswordUtilities.validate_password_strength(
            password
        )

        assert result.is_success
        assert result.value["is_strong"] is False
        assert result.value["min_length"] is False

    def test_bcrypt_password_hashing(self) -> None:
        """Test bcrypt password hashing."""
        password = "test_password_123"

        result = FlextAuthUtilities.PasswordUtilities.hash_password_bcrypt(password)

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_bcrypt_password_verification_success(self) -> None:
        """Test bcrypt password verification success."""
        password = "test_password_123"

        # Hash the password first
        hash_result = FlextAuthUtilities.PasswordUtilities.hash_password_bcrypt(
            password
        )
        assert hash_result.is_success

        # Verify it
        verify_result = FlextAuthUtilities.PasswordUtilities.verify_password_bcrypt(
            password, hash_result.value
        )

        assert verify_result.is_success
        assert verify_result.value is True

    def test_bcrypt_password_verification_failure(self) -> None:
        """Test bcrypt password verification failure."""
        password = "test_password_123"
        wrong_password = "wrong_password"

        # Hash the password first
        hash_result = FlextAuthUtilities.PasswordUtilities.hash_password_bcrypt(
            password
        )
        assert hash_result.is_success

        # Verify with wrong password
        verify_result = FlextAuthUtilities.PasswordUtilities.verify_password_bcrypt(
            wrong_password, hash_result.value
        )

        assert verify_result.is_success
        assert verify_result.value is False

    def test_session_token_creation(self) -> None:
        """Test session token creation."""
        result = FlextAuthUtilities.SessionManagement.create_session_token()

        assert result.is_success
        assert isinstance(result.value, str)
        assert len(result.value) > 0

    def test_session_creation_success(self) -> None:
        """Test session creation success."""
        user_id = "test_user"

        result = FlextAuthUtilities.SessionManagement.create_session(user_id, 3600)

        assert result.is_success
        assert result.value.user_id == user_id
        assert result.value.is_active is True
        assert result.value.expires_at > datetime.now(UTC)

    def test_session_refresh_success(self) -> None:
        """Test session refresh success."""
        session = FlextAuthModels.Session(
            session_id="test_session_id",
            session_token="test_token_that_is_long_enough_for_validation_32_chars",
            user_id="test_user",
            expires_at=datetime.now(UTC) + timedelta(hours=1),
            is_active=True,
            ip_address=None,
            user_agent=None,
        )

        result = FlextAuthUtilities.SessionManagement.refresh_session(session, 7200)

        assert result.is_success
        assert result.value.user_id == session.user_id
        assert result.value.expires_at > session.expires_at

    def test_user_role_validation_success(self) -> None:
        """Test user role validation success."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["user", "REDACTED_LDAP_BIND_PASSWORD"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.validate_user_role(user, "REDACTED_LDAP_BIND_PASSWORD")

        assert result.is_success
        assert result.value is True

    def test_user_role_validation_failure(self) -> None:
        """Test user role validation failure."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["user"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.validate_user_role(user, "REDACTED_LDAP_BIND_PASSWORD")

        assert result.is_success
        assert result.value is False

    def test_user_role_validation_no_roles(self) -> None:
        """Test user role validation with no roles."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=[],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.validate_user_role(user, "REDACTED_LDAP_BIND_PASSWORD")

        assert result.is_success
        assert result.value is False

    def test_user_permissions_validation_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test user permissions validation for REDACTED_LDAP_BIND_PASSWORD."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["REDACTED_LDAP_BIND_PASSWORD"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.validate_user_permissions(
            user, ["read", "write", "delete"]
        )

        assert result.is_success
        assert result.value is True

    def test_user_permissions_validation_user(self) -> None:
        """Test user permissions validation for regular user."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["user"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.validate_user_permissions(
            user, ["read", "write"]
        )

        assert result.is_success
        assert result.value is True

    def test_user_permissions_validation_insufficient(self) -> None:
        """Test user permissions validation with insufficient permissions."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["user"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.validate_user_permissions(
            user, ["read", "write", "delete", "REDACTED_LDAP_BIND_PASSWORD"]
        )

        assert result.is_success
        assert result.value is False

    def test_get_user_permissions_REDACTED_LDAP_BIND_PASSWORD(self) -> None:
        """Test getting user permissions for REDACTED_LDAP_BIND_PASSWORD."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["REDACTED_LDAP_BIND_PASSWORD"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.get_user_permissions(user)

        assert result.is_success
        assert isinstance(result.value, set)
        assert len(result.value) > 0

    def test_get_user_permissions_user(self) -> None:
        """Test getting user permissions for regular user."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["user"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.get_user_permissions(user)

        assert result.is_success
        assert isinstance(result.value, set)
        assert len(result.value) > 0

    def test_get_user_permissions_moderator(self) -> None:
        """Test getting user permissions for moderator."""
        user = FlextAuthModels.User(
            username="test_user",
            email="test@example.com",
            password_hash="$2b$12$test_hash_that_is_long_enough_for_validation_minimum_60_chars_required",
            full_name="Test User",
            roles=["moderator"],
            is_active=True,
            failed_login_attempts=0,
            locked_until=None,
            last_login=None,
        )

        result = FlextAuthUtilities.RoleValidation.get_user_permissions(user)

        assert result.is_success
        assert isinstance(result.value, set)
        assert "moderator" in result.value

"""Real functionality tests for flext-auth module.

This module contains comprehensive tests that verify the actual functionality
of the flext-auth system without mocking.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from flext_auth import (
    FlextAuth,
    FlextAuthConfig,
    FlextAuthModels,
)
from flext_auth.container import FlextAuthContainer

# Use unified class structure
AuthenticationResponseDict = FlextAuthModels.AuthenticationResponseDict
AuthToken = FlextAuthModels.AuthToken
User = FlextAuthModels.User

# Factory method aliases
create_session = FlextAuthContainer.create_session
create_user = FlextAuthContainer.create_user


class TestRealAuthentication:
    """Test real authentication workflows with modern Python 3.13 features."""

    def test_complete_authentication_workflow(self) -> None:
        """Test complete user lifecycle: register -> authenticate -> session -> token."""
        # Create auth instance with modern factory pattern
        config_result = FlextAuthConfig.create_for_environment("test")
        assert config_result.success, f"Config creation failed: {config_result.error}"
        auth: FlextAuth = FlextAuth(config=config_result.value)

        # Test user registration with strong typing
        register_result = auth.register_user(
            username="john_doe",
            email="john@example.com",
            password="SuperSecure123!@#",
            full_name="John Doe",
        )
        assert register_result.success, f"Registration failed: {register_result.error}"
        user = register_result.value
        assert user.username == "john_doe"
        assert user.email == "john@example.com"
        assert user.full_name == "John Doe"
        assert user.is_active
        # User is active

        # Test authentication with real password validation
        auth_result = auth.authenticate_user("john_doe", "SuperSecure123!@#")
        assert auth_result.is_success
        auth_data: AuthenticationResponseDict = auth_result.value

        # Verify auth data structure (TypedDict)
        assert "user" in auth_data
        assert "session" in auth_data
        assert "jwt_token" in auth_data
        assert "expires_at" in auth_data["session"]

        # Test JWT token validation
        jwt_token = auth_data["jwt_token"]
        assert isinstance(jwt_token, str), "jwt_token must be string"
        token_result = auth.validate_token(jwt_token)
        assert token_result.success, f"Token validation failed: {token_result.error}"
        payload = token_result.value

        # Verify token payload structure (TypedDict)
        assert payload["user_id"] is not None
        assert payload["username"] == "john_doe"
        assert isinstance(payload["exp"], (int, float))
        assert payload["exp"] > 0
        assert isinstance(payload["iat"], (int, float))
        assert payload["iat"] > 0

    def test_password_strength_and_hashing(self) -> None:
        """Test password strength validation and bcrypt hashing."""
        # Test strong password hashing through User model
        strong_password = "VerySecurePassword123!@#$%^&*()"
        user = FlextAuthModels.User(
            id="test-id", username="testuser", email="test@example.com",
        )

        # Set password
        password_result = user.set_password(strong_password)
        assert password_result.success, (
            f"Password setting failed: {password_result.error}"
        )

        # Verify bcrypt format
        assert user.password_hash.startswith("$2b$")
        assert len(user.password_hash) >= 60

        # Test verification
        verify_result = user.verify_password(strong_password)
        assert verify_result.success, (
            f"Password verification failed: {verify_result.error}"
        )
        assert verify_result.value is True

        wrong_result = user.verify_password("wrong_password")
        assert wrong_result.success
        assert wrong_result.value is False

    def test_user_management_operations(self) -> None:
        """Test user lookup and management operations."""
        auth: FlextAuth = FlextAuth()

        # Register test user
        register_result = auth.register_user(
            username="test_user", email="test@example.com", password="TestPassword123!",
        )
        assert register_result.success
        user = register_result.value
        user_id = user.id

        # Test get user by username
        user_result = auth.get_user_by_username("test_user")
        assert user_result.success
        found_user = user_result.value
        assert found_user is not None
        assert found_user.username == "test_user"
        assert found_user.id == user_id

        # Test get user by ID
        user_by_id_result = auth.get_user_by_id(user_id)
        assert user_by_id_result.success
        found_user_by_id = user_by_id_result.value
        assert found_user_by_id is not None
        assert found_user_by_id.id == user_id

        # Test case insensitive username lookup
        user_result_case = auth.get_user_by_username("TEST_USER")
        assert user_result_case.success
        found_user_case = user_result_case.value
        assert found_user_case is not None
        assert found_user_case.username == "test_user"  # Original case preserved

    def test_session_management(self) -> None:
        """Test session creation, validation, and cleanup."""
        auth: FlextAuth = FlextAuth()

        # Register and authenticate user
        register_result = auth.register_user(
            "session_user", "session@example.com", "SessionPass123!",
        )
        assert register_result.success
        user = register_result.value

        auth.authenticate_user("session_user", "SessionPass123!")

        # Get user sessions
        sessions_result = auth.get_user_sessions(user.id)
        assert sessions_result.success
        sessions = sessions_result.value
        assert len(sessions) >= 1

        # Find the session from authentication
        session = sessions[0]
        assert session.user_id == user.id
        assert not session.is_revoked
        assert not session.is_expired()

        # Test session revocation
        revoke_result = auth.revoke_session(session.id)
        assert revoke_result.success

        # Test session cleanup
        cleanup_result = auth.cleanup_expired_sessions()
        assert cleanup_result.success
        cleanup_count = cleanup_result.value
        assert isinstance(cleanup_count, int)
        assert cleanup_count >= 0

    def test_configuration_management(self) -> None:
        """Test configuration creation and management."""
        # Test environment-specific config
        config_result = FlextAuthConfig.create_for_environment("production")
        assert config_result.success
        prod_config = config_result.value
        assert prod_config.bcrypt_rounds >= 12  # Production should be secure
        assert prod_config.jwt_expiry_minutes <= 30  # Production should be short-lived

        # Test development config
        dev_config_result = FlextAuthConfig.create_for_environment("development")
        assert dev_config_result.success
        dev_config = dev_config_result.value
        assert dev_config.enable_audit_logging

        # Test custom overrides with valid session/jwt expiry relationship
        custom_config_result = FlextAuthConfig.create_for_environment(
            "test",
            jwt_expiry_minutes=60,  # JWT: 1 hour
            session_expiry_minutes=120,  # Session: 2 hours (must be > JWT)
            bcrypt_rounds=10,
            max_login_attempts=10,
        )
        assert custom_config_result.success
        custom_config = custom_config_result.value
        assert custom_config.jwt_expiry_minutes == 60
        assert custom_config.session_expiry_minutes == 120
        assert custom_config.bcrypt_rounds == 10
        assert custom_config.max_login_attempts == 10

    def test_error_handling_and_validation(self) -> None:
        """Test comprehensive error handling with FlextResult pattern."""
        auth: FlextAuth = FlextAuth()

        # Test duplicate username registration
        first_register = auth.register_user(
            "duplicate", "first@example.com", "Password123!",
        )
        assert first_register.success

        second_register = auth.register_user(
            "duplicate", "second@example.com", "Password123!",
        )
        assert second_register.is_failure
        assert (
            "duplicate" in (second_register.error or "").lower()
            or "exists" in (second_register.error or "").lower()
        )

        # Test duplicate email registration
        third_register = auth.register_user(
            "different", "first@example.com", "Password123!",
        )
        assert third_register.is_failure
        assert "email" in (third_register.error or "").lower()

        # Test invalid email format
        invalid_email_register = auth.register_user(
            "valid_user", "invalid-email", "Password123!",
        )
        assert invalid_email_register.is_failure

        # Test weak password
        weak_password_register = auth.register_user(
            "weak_user", "weak@example.com", "123",
        )
        assert weak_password_register.is_failure

        # Test authentication with non-existent user
        nonexistent_auth = auth.authenticate_user("nonexistent", "password")
        assert nonexistent_auth.is_failure
        assert (
            "invalid" in (nonexistent_auth.error or "").lower()
            or "credentials" in (nonexistent_auth.error or "").lower()
        )

        # Test authentication with wrong password
        wrong_password_auth = auth.authenticate_user("duplicate", "wrong_password")
        assert wrong_password_auth.is_failure

    def test_domain_models_validation(self) -> None:
        """Test domain models with Pydantic validation."""
        # Test User model creation with validation
        user_request = FlextAuthModels.UserCreationRequest(
            username="model_user",
            email="model@example.com",
            password="ModelPassword123!",
            full_name="Model User",
        )
        user_result = create_user(user_request)
        assert user_result.success
        user = user_result.value
        assert user.username == "model_user"
        assert user.email == "model@example.com"
        assert user.full_name == "Model User"
        assert user.password_hash.startswith("$2b$")

        # Test invalid username validation
        invalid_user_request = FlextAuthModels.UserCreationRequest(
            username="",  # Empty username should fail
            email="invalid@example.com",
            password="Password123!",
        )
        invalid_user_result = create_user(invalid_user_request)
        assert invalid_user_result.is_failure

        # Test Session model creation
        session_result = create_session(user_id=user.id)
        assert session_result.success
        session = session_result.value
        assert session.user_id == user.id
        assert not session.is_expired()
        assert session.is_valid

    def test_jwt_token_operations(self) -> None:
        """Test JWT token generation and validation with proper typing."""
        auth: FlextAuth = FlextAuth()

        # Register user for token operations
        register_result = auth.register_user(
            "jwt_user", "jwt@example.com", "JwtPassword123!",
        )
        assert register_result.success
        user = register_result.value

        # Generate JWT token
        token_result = auth.generate_jwt_token(user.id, expires_in_minutes=60)
        assert token_result.success
        jwt_token = token_result.value

        # Basic JWT format validation
        assert len(jwt_token.split(".")) == 3  # Header.Payload.Signature

        # Validate the token
        validation_result = auth.validate_token(jwt_token)
        assert validation_result.success
        payload = validation_result.value
        assert payload["user_id"] == user.id

        # Test invalid token validation
        invalid_token_result = auth.validate_token("invalid.jwt.token")
        assert invalid_token_result.is_failure

    def test_comprehensive_error_scenarios(self) -> None:
        """Test comprehensive error scenarios and edge cases."""
        # Test configuration with invalid parameters
        invalid_config_result = FlextAuthConfig.create_for_environment(
            "test",
            jwt_expiry_minutes=180,  # JWT: 3 hours
            session_expiry_minutes=60,  # Session: 1 hour (INVALID: session < JWT)
        )
        assert invalid_config_result.is_failure
        assert (
            "jwt expiry should not exceed twice the session expiry"
            in (invalid_config_result.error or "").lower()
        )

        # Test weak password validation through User model
        weak_user = FlextAuthModels.User(
            id="test-id", username="testuser", email="test@example.com",
        )
        weak_password_result = weak_user.set_password("123")  # Too weak
        assert weak_password_result.is_failure

        # Test invalid email in user creation
        invalid_user_request = FlextAuthModels.UserCreationRequest(
            username="invalid_user",
            email="not-an-email",  # Invalid email format
            password="ValidPassword123!",
        )
        invalid_user_result = create_user(invalid_user_request)
        assert invalid_user_result.is_failure

        # Test username with invalid characters
        invalid_username_request = FlextAuthModels.UserCreationRequest(
            username="user@#$%",  # Invalid characters
            email="test@valid.com",
            password="ValidPassword123!",
        )
        invalid_username_result = create_user(invalid_username_request)
        assert invalid_username_result.is_failure

    def test_convenience_methods_and_properties(self) -> None:
        """Test convenience methods and properties for full coverage."""
        # Create a user to test properties
        user_request = FlextAuthModels.UserCreationRequest(
            username="prop_user", email="prop@example.com", password="PropPassword123!",
        )
        user_result = create_user(user_request)
        assert user_result.success
        user = user_result.value

        # Test user properties
        assert user.is_active  # Should be active by default

        # Test password hash validation
        assert user.password_hash.startswith("$2b$")
        assert len(user.password_hash) >= 60

        # Test session properties
        session_result = create_session(user.id)
        assert session_result.success
        session = session_result.value

        assert not session.is_expired()  # Should not be expired when created

        # Test session methods
        session.extend_session(hours=1)

        # Test revocation
        session.revoke()
        assert session.is_revoked  # Should be revoked after revocation
        assert not session.is_valid  # Should be invalid after revocation

    def test_auth_configuration_properties(self) -> None:
        """Test auth configuration properties separately."""
        auth: FlextAuth = FlextAuth()

        # Test auth configuration properties
        security_settings = auth.config.get_security_settings()
        jwt_settings = auth.config.get_jwt_settings()

        assert isinstance(security_settings, dict)
        assert isinstance(jwt_settings, dict)
        assert "jwt_expiry_minutes" in jwt_settings
        assert "jwt_algorithm" in jwt_settings

    def test_advanced_authentication_scenarios(self) -> None:
        """Test advanced authentication scenarios for full coverage."""
        auth: FlextAuth = FlextAuth()

        # Create user for advanced testing
        user_result = auth.register_user(
            username="advanced_user",
            email="advanced@example.com",
            password="AdvancedPassword123!",
            full_name="Advanced Test User",
            roles=["REDACTED_LDAP_BIND_PASSWORD", "user"],
        )
        assert user_result.success
        user = user_result.value

        # Test role-based functionality
        assert "REDACTED_LDAP_BIND_PASSWORD" in user.roles
        assert "user" in user.roles
        assert "nonexistent" not in user.roles

        # Test user lookup methods
        user_by_id_result = auth.get_user_by_id(user.id)
        assert user_by_id_result.success
        found_user = user_by_id_result.value
        assert found_user is not None
        assert found_user.id == user.id

        # Test case-insensitive username lookup
        user_by_username_result = auth.get_user_by_username(
            "ADVANCED_USER",
        )  # Uppercase
        assert user_by_username_result.success
        found_user_case = user_by_username_result.value
        assert found_user_case is not None
        assert found_user_case.username == "advanced_user"  # Original case preserved

        # Test authentication with different cases
        auth_case_result = auth.authenticate_user(
            "ADVANCED_USER", "AdvancedPassword123!",
        )
        assert auth_case_result.success

    def test_jwt_advanced_operations(self) -> None:
        """Test advanced JWT operations and edge cases."""
        auth: FlextAuth = FlextAuth()

        # Create user for JWT testing
        user_result = auth.register_user(
            "jwt_advanced", "jwt_advanced@example.com", "JwtPassword123!",
        )
        assert user_result.success
        user = user_result.value

        # Test JWT generation with custom expiry
        jwt_result = auth.generate_jwt_token(user.id, expires_in_minutes=120)
        assert jwt_result.success
        jwt_token = jwt_result.value

        # Validate JWT structure
        jwt_parts = jwt_token.split(".")
        assert len(jwt_parts) == 3  # Header.Payload.Signature

        # Test JWT validation
        validation_result = auth.validate_token(jwt_token)
        assert validation_result.success
        payload = validation_result.value

        # Test payload content
        assert payload["user_id"] == user.id
        assert payload["username"] == "jwt_advanced"
        assert "exp" in payload
        assert "iat" in payload
        assert "iss" in payload
        assert "aud" in payload

        # Test expired/invalid tokens
        invalid_tokens = [
            "",  # Empty token
            "invalid",  # Invalid format
            "invalid.jwt",  # Invalid format
            "invalid.jwt.token",  # Invalid signature
        ]

        for invalid_token in invalid_tokens:
            invalid_result = auth.validate_token(invalid_token)
            assert invalid_result.is_failure

    def test_business_rules_validation(self) -> None:
        """Test business rules validation for full coverage."""
        # Test User business rules
        user_request = FlextAuthModels.UserCreationRequest(
            username="business_user",
            email="business@example.com",
            password="BusinessPassword123!",
        )
        user_result = create_user(user_request)
        assert user_result.success
        user = user_result.value

        # Create session for business rules testing
        session_result = create_session(user.id)
        assert session_result.success
        session = session_result.value

        # Test session is valid
        assert session.is_valid

        # Test user password functionality
        user_request = FlextAuthModels.UserCreationRequest(
            username="credential_user",
            email="credential@example.com",
            password="CredentialPassword123!",
        )
        user_result = create_user(user_request)
        assert user_result.success
        user = user_result.value

        # Test password verification
        password_verify_result = user.verify_password("CredentialPassword123!")
        assert password_verify_result.success
        assert password_verify_result.value is True

        wrong_password_result = user.verify_password("WrongPassword")
        assert wrong_password_result.success
        assert wrong_password_result.value is False

        # Test user business rules validation
        # User is valid
        assert user.is_active

    def test_factory_methods_edge_cases(self) -> None:
        """Test factory method edge cases and error paths."""
        # Test empty username
        empty_username_request = FlextAuthModels.UserCreationRequest(
            username="",  # Empty username
            email="empty@example.com",
            password="EmptyUserPassword123!",
        )
        empty_username_result = create_user(empty_username_request)
        assert empty_username_result.is_failure

        # Test empty email
        empty_email_request = FlextAuthModels.UserCreationRequest(
            username="empty_email_user",
            email="",  # Empty email
            password="EmptyEmailPassword123!",
        )
        empty_email_result = create_user(empty_email_request)
        assert empty_email_result.is_failure

        # Test extremely short session expiry
        user_request = FlextAuthModels.UserCreationRequest(
            username="session_test_user",
            email="session@test.com",
            password="SessionTest123!",
        )
        user_result = create_user(user_request)
        assert user_result.success
        user = user_result.value

        # Session with very short expiry
        short_session_result = create_session(user.id)
        assert short_session_result.success
        short_session = short_session_result.value
        assert short_session.is_valid

        # Test AuthToken creation with edge cases
        token_result = AuthToken.create_jwt_token(
            user_id=user.id,
            secret_key="test-secret-for-jwt-tokens-must-be-long-enough",
            expires_hours=1,  # Very short expiry
        )
        assert token_result.success
        auth_token = token_result.value
        assert len(auth_token.token) > 20  # Should be a proper JWT token

    def test_error_path_coverage(self) -> None:
        """Test specific error paths for coverage completion."""
        # Test verify_password with invalid credential creation
        # Create a scenario where bcrypt verification fails
        with pytest.raises(ValidationError, match="bcrypt format"):
            FlextAuthModels.User(
                id="test-id",
                username="testuser",
                email="test@example.com",
                password_hash="not_bcrypt_format",
            )

        # Test password hash validation error paths
        with pytest.raises(
            ValidationError, match="Password hash must be bcrypt format",
        ):
            # Force create a User with invalid password hash to trigger validation
            User(
                id="test_invalid_hash",
                username="test_user_invalid",
                email="test@invalid.com",
                password_hash="definitely_not_bcrypt",  # Not bcrypt format
            )

        # Test username validation error paths
        with pytest.raises(
            ValidationError,
            match="Username must contain only letters, numbers, and underscores",
        ):
            User(
                id="test_invalid_username",
                username="user@#$%",  # Invalid characters
                email="test@valid.com",
                password_hash="$2b$12$cLhrTf6WJ.otzSJ0UXjmiOTIEXh9E1OttEpE6QAQIQUUjaP43eNAO",
            )

    def test_configuration_edge_cases(self) -> None:
        """Test configuration edge cases for full coverage."""
        # Test configuration with minimal valid values
        edge_config_result = FlextAuthConfig.create_for_environment(
            "test",
            jwt_expiry_minutes=5,  # Minimum valid value
            session_expiry_minutes=5,  # Minimum valid value
            bcrypt_rounds=10,  # Minimum valid value
            max_login_attempts=3,  # Minimum valid value
        )
        assert edge_config_result.success
        edge_config = edge_config_result.value
        assert edge_config.jwt_expiry_minutes == 5
        assert edge_config.session_expiry_minutes == 5

        # Test configuration validation with invalid values (should fail)
        invalid_config_result = FlextAuthConfig.create_for_environment(
            "test",
            jwt_expiry_minutes=1,  # Below minimum (5)
            bcrypt_rounds=4,  # Below minimum (10)
        )
        assert invalid_config_result.is_failure
        assert "validation error" in (invalid_config_result.error or "").lower()

        # Test configuration validation boundaries
        boundary_config_result = FlextAuthConfig.create_for_environment(
            "production",  # Different environment
            jwt_secret="minimum-length-secret-for-jwt-token-generation-must-be-long",
            enable_audit_logging=True,
            enable_rate_limiting=True,
        )
        assert boundary_config_result.success
        boundary_config = boundary_config_result.value
        assert boundary_config.enable_audit_logging
        assert boundary_config.enable_rate_limiting

    def test_advanced_session_scenarios(self) -> None:
        """Test advanced session scenarios for coverage."""
        # Create user for session testing
        user_request = FlextAuthModels.UserCreationRequest(
            username="session_advanced_user",
            email="session_advanced@example.com",
            password="SessionAdvanced123!",
        )
        user_result = create_user(user_request)
        assert user_result.success
        user = user_result.value

        # Test session with immediate expiration (past date)
        # Create session and then manually set it to be expired
        session_result = create_session(user.id)
        assert session_result.success
        session = session_result.value

        # Test session is valid
        assert session.is_valid

        # Test manual session expiry setting (simulate expired session)
        session.expires_at = datetime.now(UTC) - timedelta(minutes=1)
        assert session.is_expired()  # Should be expired now
        assert not session.is_valid  # Should be invalid when expired
        # Session is expired

    def test_role_and_permission_advanced(self) -> None:
        """Test role and permission advanced scenarios."""
        # Create user with multiple roles and permissions
        user_request = FlextAuthModels.UserCreationRequest(
            username="role_test_user",
            email="role@test.com",
            password="RoleTest123!",
            roles=["REDACTED_LDAP_BIND_PASSWORD", "moderator", "user"],
        )
        user_result = create_user(user_request)
        assert user_result.success
        user = user_result.value

        # Test all role methods
        assert "REDACTED_LDAP_BIND_PASSWORD" in user.roles
        assert "moderator" in user.roles
        assert "user" in user.roles
        assert "superREDACTED_LDAP_BIND_PASSWORD" not in user.roles

        # Test user is active

        # Test user activation/deactivation
        assert user.is_active
        user.is_active = False
        assert not user.is_active

        # Re-activate user for further tests
        user.is_active = True
        assert user.is_active

    def test_comprehensive_authentication_edge_cases(self) -> None:
        """Test comprehensive authentication edge cases."""
        auth: FlextAuth = FlextAuth()

        # Test authentication with very long passwords
        long_password = "A" * 100 + "a1!"  # 103 chars with requirements
        user_result = auth.register_user(
            username="long_password_user",
            email="long@password.com",
            password=long_password,
        )
        assert user_result.success

        # Test authentication with the long password
        auth_long_result = auth.authenticate_user("long_password_user", long_password)
        assert auth_long_result.success

        # Test maximum length username
        max_username = "a" * 50  # MAX_USERNAME_LENGTH
        max_user_result = auth.register_user(
            username=max_username, email="max@username.com", password="MaxUsername123!",
        )
        assert max_user_result.success

        # Test lookup with maximum length username
        max_lookup_result = auth.get_user_by_username(max_username)
        assert max_lookup_result.success
        assert max_lookup_result.value is not None

        # Test minimum length username
        min_username = "abc"  # MIN_USERNAME_LENGTH = 3
        min_user_result = auth.register_user(
            username=min_username, email="min@username.com", password="MinUsername123!",
        )
        assert min_user_result.success

    def test_models_validation_edge_cases(self) -> None:
        """Test edge cases in model validation for coverage."""
        # Test invalid bcrypt hash format (covers lines 166-167 in models.py)
        with pytest.raises(ValidationError, match="bcrypt format"):
            User(
                id="test_id",
                username="test_user",
                email="test@example.com",
                password_hash="not_bcrypt_format",  # Doesn't start with $2b$
            )

        # Test invalid bcrypt hash length (covers lines 169-171 in models.py)
        with pytest.raises(ValidationError, match="bcrypt format"):
            User(
                id="test_id",
                username="test_user",
                email="test@example.com",
                password_hash="$2b$12$short",  # Valid format but too short
            )

        # Test user password verification
        user_request = FlextAuthModels.UserCreationRequest(
            username="test", email="test@example.com", password="ValidPassword123!",
        )
        valid_user_result = create_user(user_request)
        assert valid_user_result.success
        user = valid_user_result.value

        # Test password verification - correct password
        password_result = user.verify_password("ValidPassword123!")
        assert password_result.success
        assert password_result.value is True

        # Test password verification - wrong password
        wrong_password_result = user.verify_password("WrongPassword123!")
        assert wrong_password_result.success
        assert wrong_password_result.value is False

        # Test Session time remaining calculation edge cases
        session_result = create_session("test_user_id")
        assert session_result.success
        session = session_result.value

        # Test session is valid
        assert session.is_valid

    def test_factory_method_edge_cases_coverage(self) -> None:
        """Test factory method edge cases for coverage."""
        # Test FlextAuth with custom configuration
        config_result = FlextAuthConfig.create_for_environment(
            "test",
            jwt_secret="valid-jwt-secret-for-testing-purposes-must-be-long-enough",
            jwt_expiry_minutes=15,
        )
        assert config_result.success, f"Config creation failed: {config_result.error}"
        test_auth: FlextAuth = FlextAuth(config=config_result.value)

        # Test that the auth instance works properly
        user_result = test_auth.register_user(
            username="factory_test_user",
            email="factory@test.com",
            password="FactoryTest123!",
        )
        assert user_result.success

        # Test FlextAuth with production environment
        prod_config_result = FlextAuthConfig.create_for_environment(
            "production", jwt_expiry_minutes=30,
        )
        assert prod_config_result.success, (
            f"Production config failed: {prod_config_result.error}"
        )
        FlextAuth(config=prod_config_result.value)  # Test production config creation

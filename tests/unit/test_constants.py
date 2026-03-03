"""Tests for FlextAuthConstants.

Tests the authentication constants module following FLEXT standards.
"""

from __future__ import annotations

import pytest
from flext_core import FlextConstants

from flext_auth import FlextAuthConstants

c = FlextAuthConstants


class TestFlextAuthConstants:
    """Test FlextAuthConstants class and its nested constant classes."""

    def test_inherits_from_flext_constants(self) -> None:
        """Test that FlextAuthConstants inherits from FlextConstants."""
        assert issubclass(FlextAuthConstants, FlextConstants)

    def test_jwt_constants(self) -> None:
        """Test JWT-related constants."""
        jwt = FlextAuthConstants.Auth.Jwt

        assert jwt.DEFAULT_ALGORITHM == "HS256"
        assert jwt.DEFAULT_EXPIRY_MINUTES == 30
        assert jwt.MAX_EXPIRY_MINUTES == 1440
        assert jwt.ISSUER_CLAIM == "flext-auth"
        assert jwt.AUDIENCE_CLAIM == "flext-users"
        assert jwt.MIN_SECRET_KEY_LENGTH == 32
        assert jwt.DEFAULT_TOKEN_TYPE == "Bearer"

    def test_credentials_constants(self) -> None:
        """Test credential-related constants."""
        creds = FlextAuthConstants.Auth.Credentials

        assert creds.Username.MIN_LENGTH == 3
        assert creds.Username.MAX_LENGTH == 50

        assert creds.Password.MIN_LENGTH == 8
        assert creds.Password.MAX_LENGTH == 128
        assert creds.Password.MIN_SCORE == 3
        assert creds.Password.MIN_BCRYPT_HASH_LENGTH == 60
        assert creds.Password.BCRYPT_ROUNDS == 12

    def test_session_constants(self) -> None:
        """Test session-related constants."""
        session = FlextAuthConstants.Auth.Session

        assert session.DEFAULT_EXPIRY_MINUTES == 120
        assert session.MAX_EXPIRY_MINUTES == 1440
        assert session.MAX_SESSIONS_PER_USER == 5
        assert session.MIN_TOKEN_LENGTH == 32

    def test_auth_security_constants(self) -> None:
        """Test authentication security constants."""
        security = FlextAuthConstants.Auth.AuthSecurity

        assert security.MAX_LOGIN_ATTEMPTS == 5
        assert security.LOCKOUT_DURATION_MINUTES == 15
        assert security.MAX_REQUESTS_PER_MINUTE == 60
        assert security.MAX_REQUESTS_PER_HOUR == 1000

    def test_error_codes_constants(self) -> None:
        """Test error code constants."""
        codes = FlextAuthConstants.Auth.ErrorCodes

        assert codes.INVALID_CREDENTIALS == "INVALID_CREDENTIALS"
        assert codes.ACCOUNT_LOCKED == "ACCOUNT_LOCKED"
        assert codes.ACCOUNT_DISABLED == "ACCOUNT_DISABLED"
        assert codes.TOKEN_EXPIRED == "TOKEN_EXPIRED"
        assert codes.INVALID_TOKEN == "INVALID_TOKEN"

    def test_permission_types_strenum(self) -> None:
        """Test PermissionTypes StrEnum values."""
        perms = FlextAuthConstants.Auth.PermissionTypes

        assert perms.READ == "read"
        assert perms.WRITE == "write"
        assert perms.DELETE == "delete"
        assert perms.ADMIN.value == "REDACTED_LDAP_BIND_PASSWORD"

    def test_role_types_strenum(self) -> None:
        """Test RoleTypes StrEnum values."""
        roles = FlextAuthConstants.Auth.RoleTypes

        assert roles.ADMIN.value == "REDACTED_LDAP_BIND_PASSWORD"
        assert roles.USER == "user"
        assert roles.MODERATOR == "moderator"
        assert roles.GUEST == "guest"

    def test_token_types_strenum(self) -> None:
        """Test TokenTypes StrEnum values."""
        tokens = FlextAuthConstants.Auth.TokenTypes

        assert tokens.ACCESS == "access"
        assert tokens.REFRESH == "refresh"
        assert tokens.API == "api"
        assert tokens.BEARER == "bearer"

    def test_provider_types_strenum(self) -> None:
        """Test ProviderTypes StrEnum values."""
        providers = FlextAuthConstants.Auth.ProviderTypes

        assert providers.BASIC == "basic"
        assert providers.JWT == "jwt"
        assert providers.OAUTH2 == "oauth2"
        assert providers.SAML == "saml"
        assert providers.LDAP == "ldap"
        assert providers.CERTIFICATE == "certificate"
        assert providers.KERBEROS == "kerberos"
        assert providers.APIKEY == "apikey"

    def test_algorithms_strenum(self) -> None:
        """Test Algorithms StrEnum values."""
        algos = FlextAuthConstants.Auth.Algorithms

        assert algos.HS256 == "HS256"
        assert algos.RS256 == "RS256"
        assert algos.ES256 == "ES256"

    def test_valid_token_types_frozenset(self) -> None:
        """Test VALID_TOKEN_TYPES immutable collection."""
        valid = FlextAuthConstants.Auth.VALID_TOKEN_TYPES
        assert "access" in valid
        assert "refresh" in valid
        assert "api" in valid
        assert "bearer" in valid

    def test_valid_provider_types_frozenset(self) -> None:
        """Test VALID_PROVIDER_TYPES immutable collection."""
        valid = FlextAuthConstants.Auth.VALID_PROVIDER_TYPES
        assert "basic" in valid
        assert "jwt" in valid
        assert "oauth2" in valid

    def test_valid_role_types_frozenset(self) -> None:
        """Test VALID_ROLE_TYPES immutable collection."""
        valid = FlextAuthConstants.Auth.VALID_ROLE_TYPES
        assert "user" in valid
        assert "REDACTED_LDAP_BIND_PASSWORD" in valid
        assert "moderator" in valid
        assert "guest" in valid

    def test_valid_permission_types_frozenset(self) -> None:
        """Test VALID_PERMISSION_TYPES immutable collection."""
        valid = FlextAuthConstants.Auth.VALID_PERMISSION_TYPES
        assert "read" in valid
        assert "write" in valid
        assert "delete" in valid
        assert "REDACTED_LDAP_BIND_PASSWORD" in valid

    def test_configuration_defaults(self) -> None:
        """Test configuration default constants."""
        auth = FlextAuthConstants.Auth

        assert pytest.approx(30.0) == auth.DEFAULT_TIMEOUT
        assert auth.DEFAULT_MAX_RETRIES == 3
        assert auth.DEFAULT_JWT_EXPIRY_MINUTES == 1440
        assert auth.DEFAULT_SESSION_EXPIRY_MINUTES == 1440
        assert auth.DEFAULT_MAX_SESSIONS_PER_USER == 5
        assert auth.DEFAULT_HASH_ROUNDS == 12
        assert auth.DEFAULT_JWT_ALGORITHM == "HS256"

    def test_security_policy_constants(self) -> None:
        """Test security policy constants."""
        auth = FlextAuthConstants.Auth

        assert auth.MAX_ATTEMPTS_DEFAULT == 5
        assert auth.LOCKOUT_DURATION_MINUTES == 30
        assert auth.SECRET_MIN_LENGTH == 32

    def test_model_validation_constants(self) -> None:
        """Test model validation constants."""
        mv = FlextAuthConstants.Auth.ModelValidation

        assert mv.BCRYPT_ROUNDS == 12
        assert mv.DEFAULT_TOKEN_EXPIRY_MINUTES == 60
        assert mv.MAX_ROLE_NAME_LENGTH == 50
        assert mv.MAX_ROLE_DESCRIPTION_LENGTH == 500
        assert mv.MAX_PERMISSION_NAME_LENGTH == 100
        assert mv.MAX_PERMISSION_DESCRIPTION_LENGTH == 500

    def test_oauth2_constants(self) -> None:
        """Test OAuth2 constants."""
        oauth2 = FlextAuthConstants.Auth.OAuth2

        assert oauth2.SCOPE_DEFAULT == "openid profile email"
        assert "authorization_code" in oauth2.FLOWS
        assert "client_credentials" in oauth2.FLOWS
        assert oauth2.FLOW_DEFAULT == "authorization_code"
        assert oauth2.USE_PKCE_DEFAULT is True

    def test_validation_limits_mapping(self) -> None:
        """Test VALIDATION_LIMITS immutable mapping."""
        limits = FlextAuthConstants.Auth.VALIDATION_LIMITS
        assert "MAX_USERNAME_LENGTH" in limits
        assert "MIN_PASSWORD_LENGTH" in limits
        assert "DEFAULT_TIMEOUT" in limits

    def test_response_templates(self) -> None:
        """Test response template mappings."""
        success = FlextAuthConstants.Auth.SUCCESS_AUTH_RESPONSE
        assert success["status"] == "success"
        assert success["message"] == "Authentication successful"

        error = FlextAuthConstants.Auth.ERROR_AUTH_RESPONSE
        assert error["status"] == "error"

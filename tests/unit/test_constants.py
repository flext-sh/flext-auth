"""Tests for FlextAuthConstants.

Tests the authentication constants module following FLEXT standards.
"""

from __future__ import annotations

from flext_core import FlextConstants

from flext_auth.constants import FlextAuthConstants

# Import aliases following order: c -> t -> p -> r -> m -> u
# Runtime aliases defined at module level per FLEXT standards
c = FlextConstants
t = FlextMeltanoTypes if 'FlextMeltanoTypes' in globals() else None
p = FlextMeltanoProtocols if 'FlextMeltanoProtocols' in globals() else None
r = FlextResult


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
        session = FlextAuthConstants.Session

        assert session.DEFAULT_EXPIRY_MINUTES == 120
        assert session.MAX_EXPIRY_MINUTES == 1440
        assert session.MAX_SESSIONS_PER_USER == 5
        assert session.MIN_TOKEN_LENGTH == 32

    def test_auth_security_constants(self) -> None:
        """Test authentication security constants."""
        security = FlextAuthConstants.AuthSecurity

        assert security.MAX_LOGIN_ATTEMPTS == 5
        assert security.LOCKOUT_DURATION_MINUTES == 15  # Correct value from constants
        assert security.MAX_REQUESTS_PER_MINUTE == 60
        assert security.MAX_REQUESTS_PER_HOUR == 1000

    def test_error_codes_constants(self) -> None:
        """Test error code constants."""
        codes = FlextAuthConstants.ErrorCodes

        assert codes.INVALID_CREDENTIALS == "INVALID_CREDENTIALS"
        assert codes.ACCOUNT_LOCKED == "ACCOUNT_LOCKED"
        assert codes.ACCOUNT_DISABLED == "ACCOUNT_DISABLED"
        assert codes.TOKEN_EXPIRED == "TOKEN_EXPIRED"
        assert codes.INVALID_TOKEN == "INVALID_TOKEN"

    def test_permissions_constants(self) -> None:
        """Test permission constants."""
        perms = FlextAuthConstants.Permissions

        assert perms.READ == "read"
        assert perms.WRITE == "write"
        assert perms.DELETE == "delete"
        assert perms.ADMIN == "REDACTED_LDAP_BIND_PASSWORD"

        assert perms.BASIC_USER_PERMISSIONS == [perms.READ, perms.WRITE]
        assert perms.ADMIN_PERMISSIONS == [
            perms.READ,
            perms.WRITE,
            perms.DELETE,
            perms.ADMIN,
        ]

    def test_roles_constants(self) -> None:
        """Test role constants."""
        roles = FlextAuthConstants.Roles

        assert roles.ADMIN == "REDACTED_LDAP_BIND_PASSWORD"
        assert roles.USER == "user"
        assert roles.MODERATOR == "moderator"
        assert roles.GUEST == "guest"

        assert roles.DEFAULT_ROLES == [roles.USER]
        assert roles.VALID_ROLES == [
            roles.ADMIN,
            roles.USER,
            roles.MODERATOR,
            roles.GUEST,
        ]

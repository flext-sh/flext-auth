"""Tests for FlextAuthConstants."""

from __future__ import annotations

from flext_core import FlextConstants
from flext_tests import tm

from flext_auth import c


class TestFlextAuthConstants:
    """Test FlextAuthConstants class and its nested constant classes."""

    def test_inherits_from_flext_constants(self) -> None:
        tm.that(FlextConstants in c.__mro__, eq=True)

    def test_jwt_constants(self) -> None:
        jwt = c.Auth.Jwt
        tm.that(jwt.DEFAULT_ALGORITHM, eq="HS256")
        tm.that(jwt.DEFAULT_EXPIRY_MINUTES, eq=30)
        tm.that(jwt.MAX_EXPIRY_MINUTES, eq=1440)
        tm.that(jwt.ISSUER_CLAIM, eq="flext-auth")
        tm.that(jwt.AUDIENCE_CLAIM, eq="flext-users")
        tm.that(jwt.MIN_SECRET_KEY_LENGTH, eq=32)
        tm.that(jwt.DEFAULT_TOKEN_TYPE, eq="Bearer")

    def test_credentials_constants(self) -> None:
        creds = c.Auth.Credentials
        tm.that(creds.Username.MIN_LENGTH, eq=3)
        tm.that(creds.Username.MAX_LENGTH, eq=50)
        tm.that(creds.Password.MIN_LENGTH, eq=8)
        tm.that(creds.Password.MAX_LENGTH, eq=128)
        tm.that(creds.Password.MIN_SCORE, eq=3)
        tm.that(creds.Password.MIN_BCRYPT_HASH_LENGTH, eq=60)
        tm.that(creds.Password.BCRYPT_ROUNDS, eq=12)

    def test_session_constants(self) -> None:
        session = c.Auth.Session
        tm.that(session.DEFAULT_EXPIRY_MINUTES, eq=120)
        tm.that(session.MAX_EXPIRY_MINUTES, eq=1440)
        tm.that(session.MAX_SESSIONS_PER_USER, eq=5)
        tm.that(session.MIN_TOKEN_LENGTH, eq=32)

    def test_auth_security_constants(self) -> None:
        security = c.Auth.AuthSecurity
        tm.that(security.MAX_LOGIN_ATTEMPTS, eq=5)
        tm.that(security.LOCKOUT_DURATION_MINUTES, eq=15)
        tm.that(security.MAX_REQUESTS_PER_MINUTE, eq=60)
        tm.that(security.MAX_REQUESTS_PER_HOUR, eq=1000)

    def test_error_codes_constants(self) -> None:
        codes = c.Auth.ErrorCodes
        tm.that(codes.INVALID_CREDENTIALS, eq="INVALID_CREDENTIALS")
        tm.that(codes.ACCOUNT_LOCKED, eq="ACCOUNT_LOCKED")
        tm.that(codes.ACCOUNT_DISABLED, eq="ACCOUNT_DISABLED")
        tm.that(codes.TOKEN_EXPIRED, eq="TOKEN_EXPIRED")
        tm.that(codes.INVALID_TOKEN, eq="INVALID_TOKEN")

    def test_permission_types_strenum(self) -> None:
        perms = c.Auth.PermissionTypes
        tm.that(perms.READ, eq="read")
        tm.that(perms.WRITE, eq="write")
        tm.that(perms.DELETE, eq="delete")
        tm.that(perms.ADMIN.value, eq="REDACTED_LDAP_BIND_PASSWORD")

    def test_role_types_strenum(self) -> None:
        roles = c.Auth.RoleTypes
        tm.that(roles.ADMIN.value, eq="REDACTED_LDAP_BIND_PASSWORD")
        tm.that(roles.USER, eq="user")
        tm.that(roles.MODERATOR, eq="moderator")
        tm.that(roles.GUEST, eq="guest")

    def test_token_types_strenum(self) -> None:
        tokens = c.Auth.TokenTypes
        tm.that(tokens.ACCESS, eq="access")
        tm.that(tokens.REFRESH, eq="refresh")
        tm.that(tokens.API, eq="api")
        tm.that(tokens.BEARER, eq="bearer")

    def test_provider_types_strenum(self) -> None:
        providers = c.Auth.ProviderTypes
        tm.that(providers.BASIC, eq="basic")
        tm.that(providers.JWT, eq="jwt")
        tm.that(providers.OAUTH2, eq="oauth2")
        tm.that(providers.SAML, eq="saml")
        tm.that(providers.LDAP, eq="ldap")
        tm.that(providers.CERTIFICATE, eq="certificate")
        tm.that(providers.KERBEROS, eq="kerberos")
        tm.that(providers.APIKEY, eq="apikey")

    def test_algorithms_strenum(self) -> None:
        algos = c.Auth.Algorithms
        tm.that(algos.HS256, eq="HS256")
        tm.that(algos.RS256, eq="RS256")
        tm.that(algos.ES256, eq="ES256")

    def test_valid_token_types_frozenset(self) -> None:
        valid = c.Auth.VALID_TOKEN_TYPES
        tm.that("access" in valid, eq=True)
        tm.that("refresh" in valid, eq=True)
        tm.that("api" in valid, eq=True)
        tm.that("bearer" in valid, eq=True)

    def test_valid_provider_types_frozenset(self) -> None:
        valid = c.Auth.VALID_PROVIDER_TYPES
        tm.that("basic" in valid, eq=True)
        tm.that("jwt" in valid, eq=True)
        tm.that("oauth2" in valid, eq=True)

    def test_valid_role_types_frozenset(self) -> None:
        valid = c.Auth.VALID_ROLE_TYPES
        tm.that("user" in valid, eq=True)
        tm.that("REDACTED_LDAP_BIND_PASSWORD" in valid, eq=True)
        tm.that("moderator" in valid, eq=True)
        tm.that("guest" in valid, eq=True)

    def test_valid_permission_types_frozenset(self) -> None:
        valid = c.Auth.VALID_PERMISSION_TYPES
        tm.that("read" in valid, eq=True)
        tm.that("write" in valid, eq=True)
        tm.that("delete" in valid, eq=True)
        tm.that("REDACTED_LDAP_BIND_PASSWORD" in valid, eq=True)

    def test_configuration_defaults(self) -> None:
        auth = c.Auth
        tm.that(abs(auth.DEFAULT_TIMEOUT - 30.0), lt=1e-9)
        tm.that(auth.DEFAULT_MAX_RETRIES, eq=3)
        tm.that(auth.DEFAULT_JWT_EXPIRY_MINUTES, eq=1440)
        tm.that(auth.DEFAULT_SESSION_EXPIRY_MINUTES, eq=1440)
        tm.that(auth.DEFAULT_MAX_SESSIONS_PER_USER, eq=5)
        tm.that(auth.DEFAULT_HASH_ROUNDS, eq=12)
        tm.that(auth.DEFAULT_JWT_ALGORITHM, eq="HS256")

    def test_security_policy_constants(self) -> None:
        auth = c.Auth
        tm.that(auth.MAX_ATTEMPTS_DEFAULT, eq=5)
        tm.that(auth.LOCKOUT_DURATION_MINUTES, eq=30)
        tm.that(auth.SECRET_MIN_LENGTH, eq=32)

    def test_model_validation_constants(self) -> None:
        mv = c.Auth.ModelValidation
        tm.that(mv.BCRYPT_ROUNDS, eq=12)
        tm.that(mv.DEFAULT_TOKEN_EXPIRY_MINUTES, eq=60)
        tm.that(mv.MAX_ROLE_NAME_LENGTH, eq=50)
        tm.that(mv.MAX_ROLE_DESCRIPTION_LENGTH, eq=500)
        tm.that(mv.MAX_PERMISSION_NAME_LENGTH, eq=100)
        tm.that(mv.MAX_PERMISSION_DESCRIPTION_LENGTH, eq=500)

    def test_oauth2_constants(self) -> None:
        oauth2 = c.Auth.OAuth2
        tm.that(oauth2.SCOPE_DEFAULT, eq="openid profile email")
        tm.that("authorization_code" in oauth2.FLOWS, eq=True)
        tm.that("client_credentials" in oauth2.FLOWS, eq=True)
        tm.that(oauth2.FLOW_DEFAULT, eq="authorization_code")
        tm.that(oauth2.USE_PKCE_DEFAULT, eq=True)

    def test_validation_limits_mapping(self) -> None:
        limits = c.Auth.VALIDATION_LIMITS
        tm.that("MAX_USERNAME_LENGTH" in limits, eq=True)
        tm.that("MIN_PASSWORD_LENGTH" in limits, eq=True)
        tm.that("DEFAULT_TIMEOUT" in limits, eq=True)

    def test_response_templates(self) -> None:
        success = c.Auth.SUCCESS_AUTH_RESPONSE
        tm.that(success["status"], eq="success")
        tm.that(success["message"], eq="Authentication successful")
        error = c.Auth.ERROR_AUTH_RESPONSE
        tm.that(error["status"], eq="error")

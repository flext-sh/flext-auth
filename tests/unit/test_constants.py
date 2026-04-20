"""Tests for FlextAuthConstants."""

from __future__ import annotations

from flext_core import FlextConstants

from tests import c, u


class TestFlextAuthConstants:
    """Test FlextAuthConstants class and its nested constant classes."""

    def test_inherits_from_flext_constants(self) -> None:
        u.Tests.Matchers.that(c.__mro__, has=FlextConstants)

    def test_jwt_constants(self) -> None:
        jwt = c.Auth.Jwt
        u.Tests.Matchers.that(jwt.DEFAULT_ALGORITHM, eq="HS256")
        u.Tests.Matchers.that(jwt.DEFAULT_EXPIRY_MINUTES, eq=30)
        u.Tests.Matchers.that(jwt.MAX_EXPIRY_MINUTES, eq=1440)
        u.Tests.Matchers.that(jwt.ISSUER_CLAIM, eq="flext-auth")
        u.Tests.Matchers.that(jwt.AUDIENCE_CLAIM, eq="flext-users")
        u.Tests.Matchers.that(jwt.MIN_SECRET_KEY_LENGTH, eq=32)
        u.Tests.Matchers.that(jwt.DEFAULT_TOKEN_TYPE, eq="Bearer")

    def test_credentials_constants(self) -> None:
        creds = c.Auth.Credentials
        u.Tests.Matchers.that(creds.Username.MIN_LENGTH, eq=3)
        u.Tests.Matchers.that(creds.Username.MAX_LENGTH, eq=50)
        u.Tests.Matchers.that(creds.Password.MIN_LENGTH, eq=8)
        u.Tests.Matchers.that(creds.Password.MAX_LENGTH, eq=128)
        u.Tests.Matchers.that(creds.Password.MIN_SCORE, eq=3)
        u.Tests.Matchers.that(creds.Password.MIN_BCRYPT_HASH_LENGTH, eq=60)
        u.Tests.Matchers.that(creds.Password.BCRYPT_ROUNDS, eq=12)

    def test_session_constants(self) -> None:
        session = c.Auth.Session
        u.Tests.Matchers.that(session.DEFAULT_EXPIRY_MINUTES, eq=120)
        u.Tests.Matchers.that(session.MAX_EXPIRY_MINUTES, eq=1440)
        u.Tests.Matchers.that(session.MAX_SESSIONS_PER_USER, eq=5)
        u.Tests.Matchers.that(session.MIN_TOKEN_LENGTH, eq=32)

    def test_auth_security_constants(self) -> None:
        security = c.Auth.AuthSecurity
        u.Tests.Matchers.that(security.MAX_LOGIN_ATTEMPTS, eq=5)
        u.Tests.Matchers.that(security.LOCKOUT_DURATION_MINUTES, eq=15)
        u.Tests.Matchers.that(security.MAX_REQUESTS_PER_MINUTE, eq=60)
        u.Tests.Matchers.that(security.MAX_REQUESTS_PER_HOUR, eq=1000)

    def test_error_codes_constants(self) -> None:
        codes = c.Auth.ErrorCodes
        u.Tests.Matchers.that(codes.INVALID_CREDENTIALS, eq="INVALID_CREDENTIALS")
        u.Tests.Matchers.that(codes.ACCOUNT_LOCKED, eq="ACCOUNT_LOCKED")
        u.Tests.Matchers.that(codes.ACCOUNT_DISABLED, eq="ACCOUNT_DISABLED")
        u.Tests.Matchers.that(codes.TOKEN_EXPIRED, eq="TOKEN_EXPIRED")
        u.Tests.Matchers.that(codes.INVALID_TOKEN, eq="INVALID_TOKEN")

    def test_permission_types_strenum(self) -> None:
        perms = c.Auth.PermissionTypes
        u.Tests.Matchers.that(perms.READ, eq="read")
        u.Tests.Matchers.that(perms.WRITE, eq="write")
        u.Tests.Matchers.that(perms.DELETE, eq="delete")
        u.Tests.Matchers.that(perms.ADMIN.value, eq="REDACTED_LDAP_BIND_PASSWORD")

    def test_role_types_strenum(self) -> None:
        roles = c.Auth.RoleTypes
        u.Tests.Matchers.that(roles.ADMIN.value, eq="REDACTED_LDAP_BIND_PASSWORD")
        u.Tests.Matchers.that(roles.USER, eq="user")
        u.Tests.Matchers.that(roles.MODERATOR, eq="moderator")
        u.Tests.Matchers.that(roles.GUEST, eq="guest")

    def test_token_types_strenum(self) -> None:
        tokens = c.Auth.TokenTypes
        u.Tests.Matchers.that(tokens.ACCESS, eq="access")
        u.Tests.Matchers.that(tokens.REFRESH, eq="refresh")
        u.Tests.Matchers.that(tokens.API, eq="api")
        u.Tests.Matchers.that(tokens.BEARER, eq="bearer")

    def test_provider_types_strenum(self) -> None:
        providers = c.Auth.ProviderTypes
        u.Tests.Matchers.that(providers.BASIC, eq="basic")
        u.Tests.Matchers.that(providers.JWT, eq="jwt")
        u.Tests.Matchers.that(providers.OAUTH2, eq="oauth2")
        u.Tests.Matchers.that(providers.SAML, eq="saml")
        u.Tests.Matchers.that(providers.LDAP, eq="ldap")
        u.Tests.Matchers.that(providers.CERTIFICATE, eq="certificate")
        u.Tests.Matchers.that(providers.KERBEROS, eq="kerberos")
        u.Tests.Matchers.that(providers.APIKEY, eq="apikey")

    def test_algorithms_strenum(self) -> None:
        algos = c.Auth.Algorithms
        u.Tests.Matchers.that(algos.HS256, eq="HS256")
        u.Tests.Matchers.that(algos.RS256, eq="RS256")
        u.Tests.Matchers.that(algos.ES256, eq="ES256")

    def test_valid_token_types_frozenset(self) -> None:
        valid = c.Auth.VALID_TOKEN_TYPES
        u.Tests.Matchers.that(valid, has="access")
        u.Tests.Matchers.that(valid, has="refresh")
        u.Tests.Matchers.that(valid, has="api")
        u.Tests.Matchers.that(valid, has="bearer")

    def test_valid_provider_types_frozenset(self) -> None:
        valid = c.Auth.VALID_PROVIDER_TYPES
        u.Tests.Matchers.that(valid, has="basic")
        u.Tests.Matchers.that(valid, has="jwt")
        u.Tests.Matchers.that(valid, has="oauth2")

    def test_valid_role_types_frozenset(self) -> None:
        valid = c.Auth.VALID_ROLE_TYPES
        u.Tests.Matchers.that(valid, has="user")
        u.Tests.Matchers.that(valid, has="REDACTED_LDAP_BIND_PASSWORD")
        u.Tests.Matchers.that(valid, has="moderator")
        u.Tests.Matchers.that(valid, has="guest")

    def test_valid_permission_types_frozenset(self) -> None:
        valid = c.Auth.VALID_PERMISSION_TYPES
        u.Tests.Matchers.that(valid, has="read")
        u.Tests.Matchers.that(valid, has="write")
        u.Tests.Matchers.that(valid, has="delete")
        u.Tests.Matchers.that(valid, has="REDACTED_LDAP_BIND_PASSWORD")

    def test_configuration_defaults(self) -> None:
        auth = c.Auth
        u.Tests.Matchers.that(abs(auth.DEFAULT_TIMEOUT - 30.0), lt=1e-9)
        u.Tests.Matchers.that(auth.DEFAULT_MAX_RETRIES, eq=3)
        u.Tests.Matchers.that(auth.DEFAULT_JWT_EXPIRY_MINUTES, eq=1440)
        u.Tests.Matchers.that(auth.DEFAULT_SESSION_EXPIRY_MINUTES, eq=1440)
        u.Tests.Matchers.that(auth.DEFAULT_MAX_SESSIONS_PER_USER, eq=5)
        u.Tests.Matchers.that(auth.DEFAULT_HASH_ROUNDS, eq=12)
        u.Tests.Matchers.that(auth.DEFAULT_JWT_ALGORITHM, eq="HS256")

    def test_security_policy_constants(self) -> None:
        auth = c.Auth
        u.Tests.Matchers.that(auth.MAX_ATTEMPTS_DEFAULT, eq=5)
        u.Tests.Matchers.that(auth.LOCKOUT_DURATION_MINUTES, eq=30)
        u.Tests.Matchers.that(auth.SECRET_MIN_LENGTH, eq=32)

    def test_model_validation_constants(self) -> None:
        mv = c.Auth.ModelValidation
        u.Tests.Matchers.that(mv.BCRYPT_ROUNDS, eq=12)
        u.Tests.Matchers.that(mv.DEFAULT_TOKEN_EXPIRY_MINUTES, eq=60)
        u.Tests.Matchers.that(mv.MAX_ROLE_NAME_LENGTH, eq=50)
        u.Tests.Matchers.that(mv.MAX_ROLE_DESCRIPTION_LENGTH, eq=500)
        u.Tests.Matchers.that(mv.MAX_PERMISSION_NAME_LENGTH, eq=100)
        u.Tests.Matchers.that(mv.MAX_PERMISSION_DESCRIPTION_LENGTH, eq=500)

    def test_oauth2_constants(self) -> None:
        oauth2 = c.Auth.OAuth2
        u.Tests.Matchers.that(oauth2.SCOPE_DEFAULT, eq="openid profile email")
        u.Tests.Matchers.that(oauth2.FLOWS, has="authorization_code")
        u.Tests.Matchers.that(oauth2.FLOWS, has="client_credentials")
        u.Tests.Matchers.that(oauth2.FLOW_DEFAULT, eq="authorization_code")
        u.Tests.Matchers.that(oauth2.USE_PKCE_DEFAULT, eq=True)

    def test_validation_limits_mapping(self) -> None:
        limits = c.Auth.VALIDATION_LIMITS
        u.Tests.Matchers.that(limits, has="MAX_USERNAME_LENGTH")
        u.Tests.Matchers.that(limits, has="MIN_PASSWORD_LENGTH")
        u.Tests.Matchers.that(limits, has="DEFAULT_TIMEOUT")

    def test_response_templates(self) -> None:
        success = c.Auth.SUCCESS_AUTH_RESPONSE
        u.Tests.Matchers.that(success["status"], eq="success")
        u.Tests.Matchers.that(success["message"], eq="Authentication successful")
        error = c.Auth.ERROR_AUTH_RESPONSE
        u.Tests.Matchers.that(error["status"], eq="error")

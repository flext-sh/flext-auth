"""Tests for FlextAuthConstants."""

from __future__ import annotations

import pytest

from flext_core import c as core_c
from tests.constants import c
from tests.utilities import u

pytestmark = pytest.mark.usefixtures("reset_auth_singleton")


class TestsFlextAuthConstantsUnit:
    """Test FlextAuthConstants class and its nested constant classes."""

    def test_inherits_from_flext_constants(self) -> None:
        u.Tests.Matchers.that(c.__mro__, has=core_c)

    def test_jwt_constants(self) -> None:
        u.Tests.Matchers.that(c.Auth.JWT_DEFAULT_ALGORITHM, eq=c.Auth.Algorithms.HS256)
        u.Tests.Matchers.that(c.Auth.JWT_DEFAULT_EXPIRY_MINUTES, eq=30)
        u.Tests.Matchers.that(c.Auth.JWT_MAX_EXPIRY_MINUTES, eq=1440)
        u.Tests.Matchers.that(c.Auth.JWT_ISSUER_CLAIM, eq="flext-auth")
        u.Tests.Matchers.that(c.Auth.JWT_AUDIENCE_CLAIM, eq="flext-users")
        u.Tests.Matchers.that(c.Auth.JWT_MIN_SECRET_KEY_LENGTH, eq=32)
        u.Tests.Matchers.that(c.Auth.JWT_DEFAULT_TOKEN_TYPE, eq="Bearer")

    def test_credentials_constants(self) -> None:
        u.Tests.Matchers.that(c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH, eq=3)
        u.Tests.Matchers.that(c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH, eq=50)
        u.Tests.Matchers.that(c.Auth.CREDENTIALS_PASSWORD_MIN_LENGTH, eq=8)
        u.Tests.Matchers.that(c.Auth.CREDENTIALS_PASSWORD_MAX_LENGTH, eq=128)
        u.Tests.Matchers.that(c.Auth.CREDENTIALS_PASSWORD_MIN_SCORE, eq=3)
        u.Tests.Matchers.that(c.Auth.CREDENTIALS_PASSWORD_MIN_BCRYPT_HASH_LENGTH, eq=60)
        u.Tests.Matchers.that(c.Auth.CREDENTIALS_PASSWORD_BCRYPT_ROUNDS, eq=12)

    def test_session_constants(self) -> None:
        u.Tests.Matchers.that(c.Auth.SESSION_DEFAULT_EXPIRY_MINUTES, eq=120)
        u.Tests.Matchers.that(c.Auth.SESSION_MAX_EXPIRY_MINUTES, eq=1440)
        u.Tests.Matchers.that(c.Auth.SESSION_MAX_SESSIONS_PER_USER, eq=5)
        u.Tests.Matchers.that(c.Auth.SESSION_MIN_TOKEN_LENGTH, eq=32)

    def test_auth_security_constants(self) -> None:
        u.Tests.Matchers.that(c.Auth.SECURITY_MAX_LOGIN_ATTEMPTS, eq=5)
        u.Tests.Matchers.that(c.Auth.SECURITY_LOCKOUT_DURATION_MINUTES, eq=15)
        u.Tests.Matchers.that(c.Auth.SECURITY_MAX_REQUESTS_PER_MINUTE, eq=60)
        u.Tests.Matchers.that(c.Auth.SECURITY_MAX_REQUESTS_PER_HOUR, eq=1000)

    def test_error_codes_constants(self) -> None:
        u.Tests.Matchers.that(
            c.Auth.ERROR_INVALID_CREDENTIALS,
            eq="INVALID_CREDENTIALS",
        )
        u.Tests.Matchers.that(c.Auth.ERROR_ACCOUNT_LOCKED, eq="ACCOUNT_LOCKED")
        u.Tests.Matchers.that(c.Auth.ERROR_ACCOUNT_DISABLED, eq="ACCOUNT_DISABLED")
        u.Tests.Matchers.that(c.Auth.ERROR_TOKEN_EXPIRED, eq="TOKEN_EXPIRED")
        u.Tests.Matchers.that(c.Auth.ERROR_INVALID_TOKEN, eq="INVALID_TOKEN")

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
        u.Tests.Matchers.that(algos.HS256, eq=c.Auth.Algorithms.HS256)
        u.Tests.Matchers.that(algos.RS256, eq=c.Auth.Algorithms.RS256)
        u.Tests.Matchers.that(algos.ES256, eq=c.Auth.Algorithms.ES256)

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
        u.Tests.Matchers.that(auth.DEFAULT_JWT_ALGORITHM, eq=c.Auth.Algorithms.HS256)

    def test_security_policy_constants(self) -> None:
        auth = c.Auth
        u.Tests.Matchers.that(auth.MAX_ATTEMPTS_DEFAULT, eq=5)
        u.Tests.Matchers.that(auth.LOCKOUT_DURATION_MINUTES, eq=30)
        u.Tests.Matchers.that(auth.SECRET_MIN_LENGTH, eq=32)

    def test_model_validation_constants(self) -> None:
        u.Tests.Matchers.that(c.Auth.VALIDATION_BCRYPT_ROUNDS, eq=12)
        u.Tests.Matchers.that(c.Auth.VALIDATION_DEFAULT_TOKEN_EXPIRY_MINUTES, eq=60)
        u.Tests.Matchers.that(c.Auth.VALIDATION_MAX_ROLE_NAME_LENGTH, eq=50)
        u.Tests.Matchers.that(c.Auth.VALIDATION_MAX_ROLE_DESCRIPTION_LENGTH, eq=500)
        u.Tests.Matchers.that(c.Auth.VALIDATION_MAX_PERMISSION_NAME_LENGTH, eq=100)
        u.Tests.Matchers.that(
            c.Auth.VALIDATION_MAX_PERMISSION_DESCRIPTION_LENGTH,
            eq=500,
        )

    def test_oauth2_constants(self) -> None:
        u.Tests.Matchers.that(c.Auth.OAUTH2_SCOPE_DEFAULT, eq="openid profile email")
        u.Tests.Matchers.that(c.Auth.OAUTH2_FLOWS, has="authorization_code")
        u.Tests.Matchers.that(c.Auth.OAUTH2_FLOWS, has="client_credentials")
        u.Tests.Matchers.that(c.Auth.OAUTH2_FLOW_DEFAULT, eq="authorization_code")
        u.Tests.Matchers.that(c.Auth.OAUTH2_USE_PKCE_DEFAULT, eq=True)

    def test_validation_limits_mapping(self) -> None:
        limits = c.Auth.VALIDATION_LIMITS
        u.Tests.Matchers.that(limits, has="MAX_USERNAME_LENGTH")
        u.Tests.Matchers.that(limits, has="MIN_PASSWORD_LENGTH")
        u.Tests.Matchers.that(limits, has="DEFAULT_TIMEOUT")

    def test_response_templates(self) -> None:
        success = c.Auth.SUCCESS_AUTH_RESPONSE
        u.Tests.Matchers.that(success["status"], eq="success")
        u.Tests.Matchers.that(success["message"], eq="Authentication successful")

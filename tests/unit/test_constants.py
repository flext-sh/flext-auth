"""Behavioral contract tests for FlextAuthConstants.

These tests assert the observable public contract of the constants facade:
the published values callers depend on, the invariants that relate them
(derivation, ordering, membership), the immutability guarantees of the
exposed collections, and the composition reachability of the underlying
flext-core / flext-api namespaces through the facade. They intentionally
avoid poking implementation internals such as ``__mro__``.
"""

from __future__ import annotations

from enum import StrEnum

import pytest

from tests.constants import c

pytestmark = pytest.mark.usefixtures("reset_auth_singleton")


class TestsFlextAuthConstants:
    """Public-contract behavior of the FlextAuthConstants facade."""

    # ----- Composition reachability (observable, not structural) -----

    def test_core_namespace_constant_is_reachable_through_facade(self) -> None:
        # A flext-core/flext-api constant must be visible via the auth facade,
        # proving the namespaces are composed (behavior, not __mro__ inspection).
        assert c.DEFAULT_TIMEOUT_SECONDS == 30

    def test_auth_default_timeout_is_derived_from_core_timeout(self) -> None:
        assert pytest.approx(float(c.DEFAULT_TIMEOUT_SECONDS)) == c.Auth.DEFAULT_TIMEOUT

    # ----- Published scalar values (the public contract) -----

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            (c.Auth.JWT_DEFAULT_ALGORITHM, c.Auth.Algorithms.HS256),
            (c.Auth.JWT_DEFAULT_EXPIRY_MINUTES, 30),
            (c.Auth.JWT_MAX_EXPIRY_MINUTES, 1440),
            (c.Auth.JWT_ISSUER_CLAIM, "flext-auth"),
            (c.Auth.JWT_AUDIENCE_CLAIM, "flext-users"),
            (c.Auth.JWT_MIN_SECRET_KEY_LENGTH, 32),
            (c.Auth.JWT_DEFAULT_TOKEN_TYPE, "Bearer"),
            (c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH, 3),
            (c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH, 50),
            (c.Auth.CREDENTIALS_PASSWORD_MIN_LENGTH, 8),
            (c.Auth.CREDENTIALS_PASSWORD_MAX_LENGTH, 128),
            (c.Auth.CREDENTIALS_PASSWORD_MIN_SCORE, 3),
            (c.Auth.CREDENTIALS_PASSWORD_MIN_BCRYPT_HASH_LENGTH, 60),
            (c.Auth.CREDENTIALS_PASSWORD_BCRYPT_ROUNDS, 12),
            (c.Auth.SESSION_DEFAULT_EXPIRY_MINUTES, 120),
            (c.Auth.SESSION_MAX_EXPIRY_MINUTES, 1440),
            (c.Auth.SESSION_MAX_SESSIONS_PER_USER, 5),
            (c.Auth.SESSION_MIN_TOKEN_LENGTH, 32),
            (c.Auth.SECURITY_MAX_LOGIN_ATTEMPTS, 5),
            (c.Auth.SECURITY_LOCKOUT_DURATION_MINUTES, 15),
            (c.Auth.SECURITY_MAX_REQUESTS_PER_MINUTE, 60),
            (c.Auth.SECURITY_MAX_REQUESTS_PER_HOUR, 1000),
            (c.Auth.DEFAULT_MAX_RETRIES, 3),
            (c.Auth.DEFAULT_JWT_EXPIRY_MINUTES, 1440),
            (c.Auth.DEFAULT_SESSION_EXPIRY_MINUTES, 1440),
            (c.Auth.DEFAULT_MAX_SESSIONS_PER_USER, 5),
            (c.Auth.DEFAULT_HASH_ROUNDS, 12),
            (c.Auth.DEFAULT_JWT_ALGORITHM, c.Auth.Algorithms.HS256),
            (c.Auth.MAX_ATTEMPTS_DEFAULT, 5),
            (c.Auth.LOCKOUT_DURATION_MINUTES, 30),
            (c.Auth.SECRET_MIN_LENGTH, 32),
            (c.Auth.VALIDATION_BCRYPT_ROUNDS, 12),
            (c.Auth.VALIDATION_DEFAULT_TOKEN_EXPIRY_MINUTES, 60),
            (c.Auth.VALIDATION_MAX_ROLE_NAME_LENGTH, 50),
            (c.Auth.VALIDATION_MAX_ROLE_DESCRIPTION_LENGTH, 500),
            (c.Auth.VALIDATION_MAX_PERMISSION_NAME_LENGTH, 100),
            (c.Auth.VALIDATION_MAX_PERMISSION_DESCRIPTION_LENGTH, 500),
            (c.Auth.OAUTH2_SCOPE_DEFAULT, "openid profile email"),
            (c.Auth.OAUTH2_FLOW_DEFAULT, "authorization_code"),
            (c.Auth.OAUTH2_USE_PKCE_DEFAULT, True),
        ],
    )
    def test_published_scalar_constants_hold_their_contract_value(
        self,
        value: str | float | bool,
        expected: str | float | bool,
    ) -> None:
        assert value == expected

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            (c.Auth.ERROR_INVALID_CREDENTIALS, "INVALID_CREDENTIALS"),
            (c.Auth.ERROR_ACCOUNT_LOCKED, "ACCOUNT_LOCKED"),
            (c.Auth.ERROR_ACCOUNT_DISABLED, "ACCOUNT_DISABLED"),
            (c.Auth.ERROR_TOKEN_EXPIRED, "TOKEN_EXPIRED"),
            (c.Auth.ERROR_INVALID_TOKEN, "INVALID_TOKEN"),
        ],
    )
    def test_error_codes_expose_stable_machine_readable_strings(
        self,
        code: str,
        expected: str,
    ) -> None:
        assert code == expected

    # ----- StrEnum behavior: string identity + membership -----

    @pytest.mark.parametrize(
        ("member", "expected"),
        [
            (c.Auth.TokenTypes.ACCESS, "access"),
            (c.Auth.TokenTypes.REFRESH, "refresh"),
            (c.Auth.TokenTypes.API, "api"),
            (c.Auth.TokenTypes.BEARER, "bearer"),
            (c.Auth.ProviderTypes.BASIC, "basic"),
            (c.Auth.ProviderTypes.JWT, "jwt"),
            (c.Auth.ProviderTypes.OAUTH2, "oauth2"),
            (c.Auth.ProviderTypes.SAML, "saml"),
            (c.Auth.ProviderTypes.LDAP, "ldap"),
            (c.Auth.ProviderTypes.CERTIFICATE, "certificate"),
            (c.Auth.ProviderTypes.KERBEROS, "kerberos"),
            (c.Auth.ProviderTypes.APIKEY, "apikey"),
            (c.Auth.RoleTypes.ADMIN, "REDACTED_LDAP_BIND_PASSWORD"),
            (c.Auth.RoleTypes.USER, "user"),
            (c.Auth.RoleTypes.MODERATOR, "moderator"),
            (c.Auth.RoleTypes.GUEST, "guest"),
            (c.Auth.PermissionTypes.READ, "read"),
            (c.Auth.PermissionTypes.WRITE, "write"),
            (c.Auth.PermissionTypes.DELETE, "delete"),
            (c.Auth.PermissionTypes.ADMIN, "REDACTED_LDAP_BIND_PASSWORD"),
            (c.Auth.Algorithms.HS256, "HS256"),
            (c.Auth.Algorithms.RS256, "RS256"),
            (c.Auth.Algorithms.ES256, "ES256"),
        ],
    )
    def test_enum_members_are_str_equal_to_their_wire_value(
        self,
        member: StrEnum,
        expected: str,
    ) -> None:
        # StrEnum contract: a member is interchangeable with its string value.
        assert isinstance(member, str)
        assert member == expected
        assert member.value == expected

    @pytest.mark.parametrize(
        "enum_cls",
        [
            c.Auth.TokenTypes,
            c.Auth.ProviderTypes,
            c.Auth.RoleTypes,
            c.Auth.PermissionTypes,
            c.Auth.Algorithms,
        ],
    )
    def test_enum_construction_round_trips_from_wire_value(
        self,
        enum_cls: type[StrEnum],
    ) -> None:
        for member in enum_cls:
            assert enum_cls(member.value) is member

    # ----- Derivation invariants: frozensets mirror their StrEnum -----

    @pytest.mark.parametrize(
        ("valid_set", "enum_cls"),
        [
            (c.Auth.VALID_TOKEN_TYPES, c.Auth.TokenTypes),
            (c.Auth.VALID_PROVIDER_TYPES, c.Auth.ProviderTypes),
            (c.Auth.VALID_ROLE_TYPES, c.Auth.RoleTypes),
            (c.Auth.VALID_PERMISSION_TYPES, c.Auth.PermissionTypes),
        ],
    )
    def test_valid_value_set_is_exactly_the_enum_value_set(
        self,
        valid_set: frozenset[str],
        enum_cls: type[StrEnum],
    ) -> None:
        assert valid_set == {member.value for member in enum_cls}

    def test_default_jwt_algorithm_is_a_supported_algorithm(self) -> None:
        assert c.Auth.JWT_DEFAULT_ALGORITHM in {a.value for a in c.Auth.Algorithms}

    def test_default_oauth2_flow_is_a_supported_flow(self) -> None:
        assert c.Auth.OAUTH2_FLOW_DEFAULT in c.Auth.OAUTH2_FLOWS

    # ----- Ordering invariants between related bounds -----

    @pytest.mark.parametrize(
        ("low", "high"),
        [
            (c.Auth.CREDENTIALS_USERNAME_MIN_LENGTH, c.Auth.CREDENTIALS_USERNAME_MAX_LENGTH),
            (c.Auth.CREDENTIALS_PASSWORD_MIN_LENGTH, c.Auth.CREDENTIALS_PASSWORD_MAX_LENGTH),
            (c.Auth.JWT_DEFAULT_EXPIRY_MINUTES, c.Auth.JWT_MAX_EXPIRY_MINUTES),
            (c.Auth.SESSION_DEFAULT_EXPIRY_MINUTES, c.Auth.SESSION_MAX_EXPIRY_MINUTES),
        ],
    )
    def test_lower_bound_never_exceeds_its_paired_upper_bound(
        self,
        low: int,
        high: int,
    ) -> None:
        assert low <= high

    # ----- Immutability guarantees of exposed collections -----

    @pytest.mark.parametrize(
        "valid_set",
        [
            c.Auth.VALID_TOKEN_TYPES,
            c.Auth.VALID_PROVIDER_TYPES,
            c.Auth.VALID_ROLE_TYPES,
            c.Auth.VALID_PERMISSION_TYPES,
            c.Auth.OAUTH2_FLOWS,
        ],
    )
    def test_exposed_membership_sets_are_immutable(
        self,
        valid_set: frozenset[str],
    ) -> None:
        assert isinstance(valid_set, frozenset)
        with pytest.raises(AttributeError):
            valid_set.add("mutated")  # type: ignore[attr-defined]  # Why: frozenset has no add; asserting immutability.

    @pytest.mark.parametrize(
        "mapping",
        [
            c.Auth.VALIDATION_LIMITS,
            c.Auth.SUCCESS_AUTH_RESPONSE,
        ],
    )
    def test_exposed_mappings_reject_mutation(
        self,
        mapping: object,
    ) -> None:
        with pytest.raises(TypeError):
            mapping["injected"] = 1  # type: ignore[index]  # Why: MappingProxyType is read-only; asserting immutability.

    # ----- Mapping contract: required keys and payload shape -----

    @pytest.mark.parametrize(
        "key",
        ["MAX_USERNAME_LENGTH", "MIN_PASSWORD_LENGTH", "DEFAULT_TIMEOUT"],
    )
    def test_validation_limits_publishes_required_keys(self, key: str) -> None:
        assert key in c.Auth.VALIDATION_LIMITS

    def test_success_response_template_reports_success_status(self) -> None:
        response = c.Auth.SUCCESS_AUTH_RESPONSE
        assert response["status"] == "success"
        assert response["message"] == "Authentication successful"

"""Behavioral tests for the FlextAuthTypes type facade.

The public contract of a FLEXT `*Types` facade is its MRO composition and the
set of type aliases it exposes. These tests exercise that observable contract:
- the facade composes the upstream `FlextApiTypes` / `FlextAuthTypes` layers,
- the `Auth` domain namespace exposes its declared aliases and they resolve,
- upstream API-level types remain reachable through the composed facade,
- the test-scoped `Literal` aliases resolve to their promised value sets.
"""

from __future__ import annotations

import typing
from datetime import datetime

import pytest
from flext_api import FlextApiTypes

from flext_auth import FlextAuthTypes
from tests import t

pytestmark = pytest.mark.usefixtures("reset_auth_singleton")


class TestsFlextAuthTypings:
    """Observable contract of the composed FlextAuthTypes facade."""

    def test_composes_flext_api_types_via_mro(self) -> None:
        # Arrange / Act / Assert: the facade IS a specialization of the API layer.
        assert issubclass(t, FlextApiTypes)

    def test_composes_flext_auth_types_via_mro(self) -> None:
        assert issubclass(t, FlextAuthTypes)

    def test_exposes_auth_domain_namespace(self) -> None:
        assert hasattr(t, "Auth")

    def test_auth_datetime_alias_resolves_to_datetime(self) -> None:
        assert t.Auth.DateTimeValue.__value__ is datetime

    @pytest.mark.parametrize(
        "alias_name",
        [
            "DateTimeValue",
            "TokenRequestType",
            "ProvidersKey",
            "TokensClaimMap",
            "ManagersManagerValue",
            "ManagersUserData",
            "ManagersLogEntry",
            "ManagersSessionData",
            "ManagersAttemptEvents",
            "ManagersAttemptData",
        ],
    )
    def test_auth_namespace_alias_is_declared_and_resolvable(
        self, alias_name: str
    ) -> None:
        # Act: each declared alias must be a resolvable TypeAliasType member.
        alias = getattr(t.Auth, alias_name)

        # Assert: resolving its value must not raise and must yield a type form.
        assert alias.__value__ is not None

    @pytest.mark.parametrize(
        "inherited_type",
        [
            "JsonValue",
            "Scalar",
            "StrSequence",
            "MutableJsonMapping",
            "MutableMetadataMapping",
        ],
    )
    def test_upstream_api_types_reachable_through_facade(
        self, inherited_type: str
    ) -> None:
        # Assert: MRO composition keeps the upstream contract reachable.
        assert hasattr(t, inherited_type)

    @pytest.mark.parametrize(
        ("literal_name", "expected_values"),
        [
            ("TokenTypeLiteral", ("access", "refresh", "api", "bearer")),
            (
                "ProviderTypeLiteral",
                (
                    "basic",
                    "jwt",
                    "oauth2",
                    "saml",
                    "ldap",
                    "certificate",
                    "kerberos",
                    "apikey",
                ),
            ),
        ],
    )
    def test_test_scoped_literal_resolves_to_promised_values(
        self, literal_name: str, expected_values: tuple[str, ...]
    ) -> None:
        # Act: resolve the Literal alias declared in the Tests namespace.
        literal_alias = getattr(t.Tests, literal_name)

        # Assert: the allowed value set matches the published contract.
        assert typing.get_args(literal_alias.__value__) == expected_values

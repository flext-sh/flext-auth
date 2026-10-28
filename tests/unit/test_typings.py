"""Behavioral tests for the FlextAuthTypes type facade.

The public contract of a FLEXT `*Types` facade is its MRO composition and the
set of type aliases it exposes. These tests exercise that observable contract:
- the facade composes the upstream `FlextApiTypes` / `FlextAuthTypes` layers,
- the `Auth` domain namespace exposes its declared aliases and they resolve,
- upstream API-level types remain reachable through the composed facade,
- the test-scoped `Literal` aliases resolve to their promised value sets.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import typing
from datetime import datetime

import pytest
from flext_api import FlextApiTypes

from flext_auth import FlextAuthTypes
from tests import TestsFlextAuthTypes, tm


class TestsFlextAuthTypings:
    """Observable contract of the composed FlextAuthTypes facade."""

    pytestmark = pytest.mark.usefixtures("reset_auth_singleton")

    @staticmethod
    def test_composes_flext_api_types_via_mro() -> None:
        # Arrange / Act / Assert: the facade IS a specialization of the API layer.
        """Test composes flext api types via mro."""
        tm.that(FlextApiTypes in FlextAuthTypes.__mro__)

    @staticmethod
    def test_composes_flext_auth_types_via_mro() -> None:
        """Test composes flext auth types via mro."""
        tm.that(FlextAuthTypes in FlextAuthTypes.__mro__)

    @staticmethod
    def test_exposes_auth_domain_namespace() -> None:
        """Test exposes auth domain namespace."""

        def has_auth_namespace(value: type) -> bool:
            return hasattr(value, "Auth")

        tm.that(TestsFlextAuthTypes, where=has_auth_namespace)

    @staticmethod
    def test_auth_datetime_alias_resolves_to_datetime() -> None:
        """Test auth datetime alias resolves to datetime."""

        def is_datetime_alias(value: object) -> bool:
            return value is datetime

        tm.that(
            TestsFlextAuthTypes.Auth.DateTimeValue.__value__,
            where=is_datetime_alias,
        )

    @staticmethod
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
        alias_name: str,
    ) -> None:
        # Act: each declared alias must be a resolvable TypeAliasType member.
        """Test auth namespace alias is declared and resolvable."""
        alias = getattr(TestsFlextAuthTypes.Auth, alias_name)

        # Assert: resolving its value must not raise and must yield a type form.
        tm.that(alias.__value__, none=False)

    @staticmethod
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
        inherited_type: str,
    ) -> None:
        # Assert: MRO composition keeps the upstream contract reachable.
        """Test upstream api types reachable through facade."""

        def exposes_inherited_type(value: type) -> bool:
            return hasattr(value, inherited_type)

        tm.that(TestsFlextAuthTypes, where=exposes_inherited_type)

    @staticmethod
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
        literal_name: str,
        expected_values: TestsFlextAuthTypes.VariadicTuple[str],
    ) -> None:
        # Act: resolve the Literal alias declared in the Tests namespace.
        """Test test scoped literal resolves to promised values."""
        literal_alias = getattr(TestsFlextAuthTypes.Tests, literal_name)

        # Assert: the allowed value set matches the published contract.
        tm.that(typing.get_args(literal_alias.__value__), eq=expected_values)

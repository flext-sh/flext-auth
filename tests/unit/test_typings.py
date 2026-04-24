"""Tests for FlextAuthTypes MRO inheritance."""

from __future__ import annotations

from flext_api import FlextApiTypes

from tests import t, u


class TestsFlextAuthTypesUnit:
    """Test FlextAuthTypes MRO inheritance."""

    def test_inherits_from_flext_api_types(self) -> None:
        u.Tests.Matchers.that(t.__mro__, has=FlextApiTypes)

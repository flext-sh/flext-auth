"""Tests for FlextAuthTypes MRO inheritance."""

from __future__ import annotations

import pytest
from flext_api import FlextApiTypes

from tests.typings import t
from tests.utilities import u

pytestmark = pytest.mark.usefixtures("reset_auth_singleton")


class TestsFlextAuthTypesUnit:
    """Test FlextAuthTypes MRO inheritance."""

    def test_inherits_from_flext_api_types(self) -> None:
        u.Tests.Matchers.that(t.__mro__, has=FlextApiTypes)

"""Comprehensive tests for FlextAuth API."""

from __future__ import annotations

import pytest

from tests.unit.api_cases.case_01 import TestsFlextAuthApiCase01 as _ApiCase01
from tests.unit.api_cases.case_02 import TestsFlextAuthApiCase02 as _ApiCase02
from tests.unit.api_cases.case_03 import TestsFlextAuthApiCase03 as _ApiCase03
from tests.unit.api_cases.case_04 import TestsFlextAuthApiCase04 as _ApiCase04
from tests.unit.api_cases.case_05 import TestsFlextAuthApiCase05 as _ApiCase05
from tests.unit.api_cases.case_06 import TestsFlextAuthApiCase06 as _ApiCase06
from tests.unit.api_cases.case_07 import TestsFlextAuthApiCase07 as _ApiCase07
from tests.unit.api_cases.case_08 import TestsFlextAuthApiCase08 as _ApiCase08
from tests.unit.api_cases.case_09 import TestsFlextAuthApiCase09 as _ApiCase09
from tests.unit.api_cases.case_10 import TestsFlextAuthApiCase10 as _ApiCase10
from tests.unit.api_cases.case_11 import TestsFlextAuthApiCase11 as _ApiCase11

pytestmark = pytest.mark.usefixtures("reset_auth_singleton")


class TestsFlextAuthApi(
    _ApiCase01,
    _ApiCase02,
    _ApiCase03,
    _ApiCase04,
    _ApiCase05,
    _ApiCase06,
    _ApiCase07,
    _ApiCase08,
    _ApiCase09,
    _ApiCase10,
    _ApiCase11,
):
    """FlextAuth API test facade preserving the public test class."""


__all__: list[str] = ["TestsFlextAuthApi"]

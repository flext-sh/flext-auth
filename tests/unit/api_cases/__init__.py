# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit.api Cases package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from tests.unit.api_cases.case_01 import TestsFlextAuthApiCase01
    from tests.unit.api_cases.case_02 import TestsFlextAuthApiCase02
    from tests.unit.api_cases.case_03 import TestsFlextAuthApiCase03
    from tests.unit.api_cases.case_04 import TestsFlextAuthApiCase04
    from tests.unit.api_cases.case_05 import TestsFlextAuthApiCase05
    from tests.unit.api_cases.case_06 import TestsFlextAuthApiCase06
    from tests.unit.api_cases.case_07 import TestsFlextAuthApiCase07
    from tests.unit.api_cases.case_08 import TestsFlextAuthApiCase08
    from tests.unit.api_cases.case_09 import TestsFlextAuthApiCase09
    from tests.unit.api_cases.case_10 import TestsFlextAuthApiCase10
    from tests.unit.api_cases.case_11 import TestsFlextAuthApiCase11
    from tests.unit.api_cases.support import TestsFlextAuthApiTestDataHelper


__all__: tuple[str, ...] = (
    "TestsFlextAuthApiCase01",
    "TestsFlextAuthApiCase02",
    "TestsFlextAuthApiCase03",
    "TestsFlextAuthApiCase04",
    "TestsFlextAuthApiCase05",
    "TestsFlextAuthApiCase06",
    "TestsFlextAuthApiCase07",
    "TestsFlextAuthApiCase08",
    "TestsFlextAuthApiCase09",
    "TestsFlextAuthApiCase10",
    "TestsFlextAuthApiCase11",
    "TestsFlextAuthApiTestDataHelper",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".case_01": ("TestsFlextAuthApiCase01",),
            ".case_02": ("TestsFlextAuthApiCase02",),
            ".case_03": ("TestsFlextAuthApiCase03",),
            ".case_04": ("TestsFlextAuthApiCase04",),
            ".case_05": ("TestsFlextAuthApiCase05",),
            ".case_06": ("TestsFlextAuthApiCase06",),
            ".case_07": ("TestsFlextAuthApiCase07",),
            ".case_08": ("TestsFlextAuthApiCase08",),
            ".case_09": ("TestsFlextAuthApiCase09",),
            ".case_10": ("TestsFlextAuthApiCase10",),
            ".case_11": ("TestsFlextAuthApiCase11",),
            ".support": ("TestsFlextAuthApiTestDataHelper",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    ),
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

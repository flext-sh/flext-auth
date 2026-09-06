# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests.unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import api_cases as api_cases
    from flext_tests import c, d, e, h, m, p, r, s, t, td, tf, tk, tm, tv, u, x

    from .api_cases.case_01 import TestsFlextAuthApiCase01
    from .api_cases.case_02 import TestsFlextAuthApiCase02
    from .api_cases.case_03 import TestsFlextAuthApiCase03
    from .api_cases.case_04 import TestsFlextAuthApiCase04
    from .api_cases.case_05 import TestsFlextAuthApiCase05
    from .api_cases.case_06 import TestsFlextAuthApiCase06
    from .api_cases.case_07 import TestsFlextAuthApiCase07
    from .api_cases.case_08 import TestsFlextAuthApiCase08
    from .api_cases.case_09 import TestsFlextAuthApiCase09
    from .api_cases.case_10 import TestsFlextAuthApiCase10
    from .api_cases.case_11 import TestsFlextAuthApiCase11
    from .api_cases.support import FlextAuthApiTestDataHelper
    from .test_api import TestsFlextAuthApi
    from .test_config import TestsFlextAuthConfig
    from .test_constants import TestsFlextAuthConstants
    from .test_token_real_flows import TestsFlextAuthTokenRealFlows
    from .test_typings import TestsFlextAuthTypings
__all__: tuple[str, ...] = (
    "FlextAuthApiTestDataHelper",
    "TestsFlextAuthApi",
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
    "TestsFlextAuthConfig",
    "TestsFlextAuthConstants",
    "TestsFlextAuthTokenRealFlows",
    "TestsFlextAuthTypings",
    "api_cases",
    "c",
    "d",
    "e",
    "h",
    "m",
    "p",
    "r",
    "s",
    "t",
    "td",
    "tf",
    "tk",
    "tm",
    "tv",
    "u",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".api_cases": ("api_cases",),
            ".api_cases.case_01": ("TestsFlextAuthApiCase01",),
            ".api_cases.case_02": ("TestsFlextAuthApiCase02",),
            ".api_cases.case_03": ("TestsFlextAuthApiCase03",),
            ".api_cases.case_04": ("TestsFlextAuthApiCase04",),
            ".api_cases.case_05": ("TestsFlextAuthApiCase05",),
            ".api_cases.case_06": ("TestsFlextAuthApiCase06",),
            ".api_cases.case_07": ("TestsFlextAuthApiCase07",),
            ".api_cases.case_08": ("TestsFlextAuthApiCase08",),
            ".api_cases.case_09": ("TestsFlextAuthApiCase09",),
            ".api_cases.case_10": ("TestsFlextAuthApiCase10",),
            ".api_cases.case_11": ("TestsFlextAuthApiCase11",),
            ".api_cases.support": ("FlextAuthApiTestDataHelper",),
            ".test_api": ("TestsFlextAuthApi",),
            ".test_config": ("TestsFlextAuthConfig",),
            ".test_constants": ("TestsFlextAuthConstants",),
            ".test_token_real_flows": ("TestsFlextAuthTokenRealFlows",),
            ".test_typings": ("TestsFlextAuthTypings",),
            "flext_tests": (
                "c",
                "d",
                "e",
                "h",
                "m",
                "p",
                "r",
                "s",
                "t",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "u",
                "x",
            ),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

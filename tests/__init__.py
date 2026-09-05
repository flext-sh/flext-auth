# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import fixtures as fixtures
    from . import unit as unit
    from flext_tests import FlextTestsConstants, d, e, h, r, td, tf, tk, tm, tv, x
    from typing import Final

    from .base import TestsFlextAuthServiceBase, TestsFlextAuthServiceBase as s
    from .constants import TestsFlextAuthConstants, TestsFlextAuthConstants as c
    from .models import (
        CertificateFixture,
        TestsFlextAuthModels,
        TestsFlextAuthModels as m,
    )
    from .protocols import TestsFlextAuthProtocols, TestsFlextAuthProtocols as p
    from .settings import TestsFlextAuthSettings
    from .typings import TestsFlextAuthTypes, TestsFlextAuthTypes as t
    from .unit.api_cases.case_01 import TestsFlextAuthApiCase01
    from .unit.api_cases.case_02 import TestsFlextAuthApiCase02
    from .unit.api_cases.case_03 import TestsFlextAuthApiCase03
    from .unit.api_cases.case_04 import TestsFlextAuthApiCase04
    from .unit.api_cases.case_05 import TestsFlextAuthApiCase05
    from .unit.api_cases.case_06 import TestsFlextAuthApiCase06
    from .unit.api_cases.case_07 import TestsFlextAuthApiCase07
    from .unit.api_cases.case_08 import TestsFlextAuthApiCase08
    from .unit.api_cases.case_09 import TestsFlextAuthApiCase09
    from .unit.api_cases.case_10 import TestsFlextAuthApiCase10
    from .unit.api_cases.case_11 import TestsFlextAuthApiCase11
    from .unit.api_cases.support import FlextAuthApiTestDataHelper
    from .utilities import TestsFlextAuthUtilities, TestsFlextAuthUtilities as u
__all__: tuple[str, ...] = (
    "CertificateFixture",
    "Final",
    "FlextAuthApiTestDataHelper",
    "FlextTestsConstants",
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
    "TestsFlextAuthConstants",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthServiceBase",
    "TestsFlextAuthSettings",
    "TestsFlextAuthTypes",
    "TestsFlextAuthUtilities",
    "c",
    "d",
    "e",
    "fixtures",
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
    "unit",
    "x",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".base": ("TestsFlextAuthServiceBase", "s"),
            ".constants": ("TestsFlextAuthConstants", "c"),
            ".fixtures": ("fixtures",),
            ".models": ("CertificateFixture", "TestsFlextAuthModels", "m"),
            ".protocols": ("TestsFlextAuthProtocols", "p"),
            ".settings": ("TestsFlextAuthSettings",),
            ".typings": ("TestsFlextAuthTypes", "t"),
            ".unit": ("unit",),
            ".unit.api_cases.case_01": ("TestsFlextAuthApiCase01",),
            ".unit.api_cases.case_02": ("TestsFlextAuthApiCase02",),
            ".unit.api_cases.case_03": ("TestsFlextAuthApiCase03",),
            ".unit.api_cases.case_04": ("TestsFlextAuthApiCase04",),
            ".unit.api_cases.case_05": ("TestsFlextAuthApiCase05",),
            ".unit.api_cases.case_06": ("TestsFlextAuthApiCase06",),
            ".unit.api_cases.case_07": ("TestsFlextAuthApiCase07",),
            ".unit.api_cases.case_08": ("TestsFlextAuthApiCase08",),
            ".unit.api_cases.case_09": ("TestsFlextAuthApiCase09",),
            ".unit.api_cases.case_10": ("TestsFlextAuthApiCase10",),
            ".unit.api_cases.case_11": ("TestsFlextAuthApiCase11",),
            ".unit.api_cases.support": ("FlextAuthApiTestDataHelper",),
            ".utilities": ("TestsFlextAuthUtilities", "u"),
            "flext_tests": (
                "FlextTestsConstants",
                "d",
                "e",
                "h",
                "r",
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
                "x",
            ),
            "typing": ("Final",),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

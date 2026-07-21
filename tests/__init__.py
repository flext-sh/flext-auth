# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_tests import (
        d as d,
        e as e,
        h as h,
        r as r,
        td as td,
        tf as tf,
        tk as tk,
        tm as tm,
        tv as tv,
        x as x,
    )

    from tests.base import (
        TestsFlextAuthServiceBase as TestsFlextAuthServiceBase,
        s as s,
    )
    from tests.constants import (
        TestsFlextAuthConstants as TestsFlextAuthConstants,
        c as c,
    )
    from tests.models import (
        CertificateFixture as CertificateFixture,
        TestsFlextAuthModels as TestsFlextAuthModels,
        m as m,
    )
    from tests.protocols import TestsFlextAuthProtocols as TestsFlextAuthProtocols, p
    from tests.settings import TestsFlextAuthSettings as TestsFlextAuthSettings
    from tests.typings import TestsFlextAuthTypes as TestsFlextAuthTypes, t as t
    from tests.unit.api_cases.case_01 import (
        TestsFlextAuthApiCase01 as TestsFlextAuthApiCase01,
    )
    from tests.unit.api_cases.case_02 import (
        TestsFlextAuthApiCase02 as TestsFlextAuthApiCase02,
    )
    from tests.unit.api_cases.case_03 import (
        TestsFlextAuthApiCase03 as TestsFlextAuthApiCase03,
    )
    from tests.unit.api_cases.case_04 import (
        TestsFlextAuthApiCase04 as TestsFlextAuthApiCase04,
    )
    from tests.unit.api_cases.case_05 import (
        TestsFlextAuthApiCase05 as TestsFlextAuthApiCase05,
    )
    from tests.unit.api_cases.case_06 import (
        TestsFlextAuthApiCase06 as TestsFlextAuthApiCase06,
    )
    from tests.unit.api_cases.case_07 import (
        TestsFlextAuthApiCase07 as TestsFlextAuthApiCase07,
    )
    from tests.unit.api_cases.case_08 import (
        TestsFlextAuthApiCase08 as TestsFlextAuthApiCase08,
    )
    from tests.unit.api_cases.case_09 import (
        TestsFlextAuthApiCase09 as TestsFlextAuthApiCase09,
    )
    from tests.unit.api_cases.case_10 import (
        TestsFlextAuthApiCase10 as TestsFlextAuthApiCase10,
    )
    from tests.unit.api_cases.case_11 import (
        TestsFlextAuthApiCase11 as TestsFlextAuthApiCase11,
    )
    from tests.unit.api_cases.support import (
        FlextAuthApiTestDataHelper as FlextAuthApiTestDataHelper,
    )
    from tests.unit.test_api import TestsFlextAuthApi as TestsFlextAuthApi
    from tests.unit.test_config import TestsFlextAuthConfig as TestsFlextAuthConfig
    from tests.unit.test_token_real_flows import (
        TestsFlextAuthTokenRealFlows as TestsFlextAuthTokenRealFlows,
    )
    from tests.unit.test_typings import TestsFlextAuthTypings as TestsFlextAuthTypings
    from tests.utilities import TestsFlextAuthUtilities as TestsFlextAuthUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".fixtures",
        ".unit",
    ),
    build_lazy_import_map(
        {
            ".base": (
                "TestsFlextAuthServiceBase",
                "s",
            ),
            ".conftest": ("conftest",),
            ".constants": (
                "TestsFlextAuthConstants",
                "c",
            ),
            ".fixtures": ("fixtures",),
            ".models": (
                "CertificateFixture",
                "TestsFlextAuthModels",
                "m",
            ),
            ".protocols": (
                "TestsFlextAuthProtocols",
                "p",
            ),
            ".settings": ("TestsFlextAuthSettings",),
            ".typings": (
                "TestsFlextAuthTypes",
                "t",
            ),
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
            ".unit.test_api": ("TestsFlextAuthApi",),
            ".unit.test_config": ("TestsFlextAuthConfig",),
            ".unit.test_token_real_flows": ("TestsFlextAuthTokenRealFlows",),
            ".unit.test_typings": ("TestsFlextAuthTypings",),
            ".utilities": (
                "TestsFlextAuthUtilities",
                "u",
            ),
            "flext_tests": (
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
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

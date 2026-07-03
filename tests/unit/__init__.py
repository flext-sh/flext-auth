# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_auth.tests.unit.api_cases.case_01 import (
        TestsFlextAuthApiCase01 as TestsFlextAuthApiCase01,
    )
    from flext_auth.tests.unit.api_cases.case_02 import (
        TestsFlextAuthApiCase02 as TestsFlextAuthApiCase02,
    )
    from flext_auth.tests.unit.api_cases.case_03 import (
        TestsFlextAuthApiCase03 as TestsFlextAuthApiCase03,
    )
    from flext_auth.tests.unit.api_cases.case_04 import (
        TestsFlextAuthApiCase04 as TestsFlextAuthApiCase04,
    )
    from flext_auth.tests.unit.api_cases.case_05 import (
        TestsFlextAuthApiCase05 as TestsFlextAuthApiCase05,
    )
    from flext_auth.tests.unit.api_cases.case_06 import (
        TestsFlextAuthApiCase06 as TestsFlextAuthApiCase06,
    )
    from flext_auth.tests.unit.api_cases.case_07 import (
        TestsFlextAuthApiCase07 as TestsFlextAuthApiCase07,
    )
    from flext_auth.tests.unit.api_cases.case_08 import (
        TestsFlextAuthApiCase08 as TestsFlextAuthApiCase08,
    )
    from flext_auth.tests.unit.api_cases.case_09 import (
        TestsFlextAuthApiCase09 as TestsFlextAuthApiCase09,
    )
    from flext_auth.tests.unit.api_cases.case_10 import (
        TestsFlextAuthApiCase10 as TestsFlextAuthApiCase10,
    )
    from flext_auth.tests.unit.api_cases.case_11 import (
        TestsFlextAuthApiCase11 as TestsFlextAuthApiCase11,
    )
    from flext_auth.tests.unit.api_cases.support import (
        FlextAuthApiTestDataHelper as FlextAuthApiTestDataHelper,
    )
    from flext_auth.tests.unit.test_api import TestsFlextAuthApi as TestsFlextAuthApi
    from flext_auth.tests.unit.test_config import (
        TestsFlextAuthConfig as TestsFlextAuthConfig,
    )
    from flext_auth.tests.unit.test_constants import (
        TestsFlextAuthConstantsUnit as TestsFlextAuthConstantsUnit,
    )
    from flext_auth.tests.unit.test_token_real_flows import (
        TestsFlextAuthTokenRealFlows as TestsFlextAuthTokenRealFlows,
    )
    from flext_auth.tests.unit.test_typings import (
        TestsFlextAuthTypesUnit as TestsFlextAuthTypesUnit,
    )
_LAZY_IMPORTS = merge_lazy_imports(
    (".api_cases",),
    build_lazy_import_map(
        {
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
            ".test_constants": ("TestsFlextAuthConstantsUnit",),
            ".test_token_real_flows": ("TestsFlextAuthTokenRealFlows",),
            ".test_typings": ("TestsFlextAuthTypesUnit",),
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

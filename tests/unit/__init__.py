# AUTO-GENERATED FILE — Regenerate with: make gen
"""Unit package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
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

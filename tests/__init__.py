# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

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
            ".fixtures.certificates": ("CertificateFixture",),
            ".models": (
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
            ".unit.test_constants": ("TestsFlextAuthConstantsUnit",),
            ".unit.test_token_real_flows": ("TestsFlextAuthTokenRealFlows",),
            ".unit.test_typings": ("TestsFlextAuthTypesUnit",),
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

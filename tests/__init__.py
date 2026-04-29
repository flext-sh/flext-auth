# AUTO-GENERATED FILE — Regenerate with: make gen
"""Tests package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if _t.TYPE_CHECKING:
    from flext_tests import td, tf, tk, tm, tv

    from flext_auth import d, e, h, r, s, x
    from tests.constants import TestsFlextAuthConstants, c
    from tests.fixtures.certificates import CertificateFixture
    from tests.models import TestsFlextAuthModels, m
    from tests.protocols import TestsFlextAuthProtocols, p
    from tests.typings import TestsFlextAuthTypes, t
    from tests.unit.test_api import TestsFlextAuthApi
    from tests.unit.test_config import TestsFlextAuthConfig
    from tests.unit.test_constants import TestsFlextAuthConstantsUnit
    from tests.unit.test_token_real_flows import TestsFlextAuthTokenRealFlows
    from tests.unit.test_typings import TestsFlextAuthTypesUnit
    from tests.utilities import TestsFlextAuthUtilities, u
_LAZY_IMPORTS = merge_lazy_imports(
    (
        ".fixtures",
        ".unit",
    ),
    build_lazy_import_map(
        {
            ".constants": (
                "TestsFlextAuthConstants",
                "c",
            ),
            ".fixtures.certificates": ("CertificateFixture",),
            ".models": (
                "TestsFlextAuthModels",
                "m",
            ),
            ".protocols": (
                "TestsFlextAuthProtocols",
                "p",
            ),
            ".typings": (
                "TestsFlextAuthTypes",
                "t",
            ),
            ".unit.test_api": ("TestsFlextAuthApi",),
            ".unit.test_config": ("TestsFlextAuthConfig",),
            ".unit.test_constants": ("TestsFlextAuthConstantsUnit",),
            ".unit.test_token_real_flows": ("TestsFlextAuthTokenRealFlows",),
            ".unit.test_typings": ("TestsFlextAuthTypesUnit",),
            ".utilities": (
                "TestsFlextAuthUtilities",
                "u",
            ),
            "flext_auth": (
                "d",
                "e",
                "h",
                "r",
                "s",
                "x",
            ),
            "flext_tests": (
                "td",
                "tf",
                "tk",
                "tm",
                "tv",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "CertificateFixture",
    "TestsFlextAuthApi",
    "TestsFlextAuthConfig",
    "TestsFlextAuthConstants",
    "TestsFlextAuthConstantsUnit",
    "TestsFlextAuthModels",
    "TestsFlextAuthProtocols",
    "TestsFlextAuthTokenRealFlows",
    "TestsFlextAuthTypes",
    "TestsFlextAuthTypesUnit",
    "TestsFlextAuthUtilities",
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
]

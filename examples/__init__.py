# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from examples._utilities.example_utilities import (
        FlextAuthExampleUtilities as FlextAuthExampleUtilities,
    )
    from examples.advanced_features_02 import (
        FlextAuthAdvancedFeaturesExample as FlextAuthAdvancedFeaturesExample,
    )
    from examples.basic_auth_05 import (
        FlextAuthBasicAuthExample as FlextAuthBasicAuthExample,
    )
    from examples.basic_refactored_usage_06 import FlextAuthDemo as FlextAuthDemo
    from examples.basic_usage_01 import (
        FlextAuthBasicUsageExample as FlextAuthBasicUsageExample,
    )
    from examples.basic_usage_07 import (
        FlextAuthBasicUsagePortugueseExample as FlextAuthBasicUsagePortugueseExample,
    )
    from examples.basic_usage_flows import (
        FlextAuthBasicUsageFlows as FlextAuthBasicUsageFlows,
    )
    from examples.basic_usage_workflow import (
        FlextAuthBasicUsageWorkflow as FlextAuthBasicUsageWorkflow,
    )
    from examples.comprehensive_demo_03 import (
        FlextAuthComprehensiveDemo as FlextAuthComprehensiveDemo,
    )
    from examples.debug_auth_issues_09 import (
        FlextAuthDebugIssuesExample as FlextAuthDebugIssuesExample,
    )
    from examples.flext_config_usage import (
        FlextAuthConfigUsageExample as FlextAuthConfigUsageExample,
    )
    from examples.refactored_system_showcase_04 import (
        FlextAuthRefactoredSystemShowcaseExample as FlextAuthRefactoredSystemShowcaseExample,
    )
    from examples.simple_usage_08 import (
        FlextAuthSimpleUsageExample as FlextAuthSimpleUsageExample,
    )
    from flext_core._root_typing_parts import (
        c as c,
        d as d,
        e as e,
        h as h,
        m as m,
        p as p,
        r as r,
        s as s,
        t as t,
        u as u,
        x as x,
    )
_LAZY_IMPORTS = merge_lazy_imports(
    ("._utilities",),
    build_lazy_import_map(
        {
            "._utilities": ("_utilities",),
            "._utilities.example_utilities": ("FlextAuthExampleUtilities",),
            ".advanced_features_02": ("FlextAuthAdvancedFeaturesExample",),
            ".basic_auth_05": ("FlextAuthBasicAuthExample",),
            ".basic_refactored_usage_06": ("FlextAuthDemo",),
            ".basic_usage_01": ("FlextAuthBasicUsageExample",),
            ".basic_usage_07": ("FlextAuthBasicUsagePortugueseExample",),
            ".basic_usage_flows": ("FlextAuthBasicUsageFlows",),
            ".basic_usage_workflow": ("FlextAuthBasicUsageWorkflow",),
            ".comprehensive_demo_03": ("FlextAuthComprehensiveDemo",),
            ".debug_auth_issues_09": ("FlextAuthDebugIssuesExample",),
            ".flext_config_usage": ("FlextAuthConfigUsageExample",),
            ".refactored_system_showcase_04": (
                "FlextAuthRefactoredSystemShowcaseExample",
            ),
            ".simple_usage_08": ("FlextAuthSimpleUsageExample",),
            "flext_core._root_typing_parts": (
                "c",
                "d",
                "e",
                "h",
                "m",
                "p",
                "r",
                "s",
                "t",
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

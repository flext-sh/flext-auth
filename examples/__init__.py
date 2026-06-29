# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
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
        ".refactored_system_showcase_04": ("FlextAuthRefactoredSystemShowcaseExample",),
        ".simple_usage_08": ("FlextAuthSimpleUsageExample",),
        ".utils": ("FlextAuthExampleUtilities",),
        "flext_auth": (
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
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from types import MappingProxyType

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from . import _utilities as _utilities
    from flext_auth import c, d, e, h, m, p, r, s, t, u, x

    from ._utilities.example_utilities import FlextAuthExampleUtilities
    from .advanced_features_02 import FlextAuthAdvancedFeaturesExample
    from .basic_auth_05 import FlextAuthBasicAuthExample
    from .basic_refactored_usage_06 import FlextAuthDemo
    from .basic_usage_01 import FlextAuthBasicUsageExample
    from .basic_usage_07 import FlextAuthBasicUsagePortugueseExample
    from .basic_usage_flows import FlextAuthBasicUsageFlows
    from .basic_usage_workflow import FlextAuthBasicUsageWorkflow
    from .comprehensive_demo_03 import FlextAuthComprehensiveDemo
    from .debug_auth_issues_09 import FlextAuthDebugIssuesExample
    from .flext_config_usage import FlextAuthConfigUsageExample
    from .refactored_system_showcase_04 import FlextAuthRefactoredSystemShowcaseExample
    from .simple_usage_08 import FlextAuthSimpleUsageExample
__all__: tuple[str, ...] = (
    "FlextAuthAdvancedFeaturesExample",
    "FlextAuthBasicAuthExample",
    "FlextAuthBasicUsageExample",
    "FlextAuthBasicUsageFlows",
    "FlextAuthBasicUsagePortugueseExample",
    "FlextAuthBasicUsageWorkflow",
    "FlextAuthComprehensiveDemo",
    "FlextAuthConfigUsageExample",
    "FlextAuthDebugIssuesExample",
    "FlextAuthDemo",
    "FlextAuthExampleUtilities",
    "FlextAuthRefactoredSystemShowcaseExample",
    "FlextAuthSimpleUsageExample",
    "_utilities",
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
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
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
            "flext_auth": ("c", "d", "e", "h", "m", "p", "r", "s", "t", "u", "x"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

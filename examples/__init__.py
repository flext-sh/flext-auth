# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth import c, d, e, h, m, p, r, s, t, u, x
    from .advanced_features_02 import FlextAuthAdvancedFeaturesExample
    from .basic_auth_05 import FlextAuthBasicAuthExample
    from .basic_usage_01 import FlextAuthBasicUsageExample
    from .basic_usage_07 import FlextAuthBasicUsagePortugueseExample
    from .basic_usage_flows import FlextAuthBasicUsageFlows
    from .basic_usage_workflow import FlextAuthBasicUsageWorkflow
    from .flext_config_usage import FlextAuthConfigUsageExample
    from .refactored_system_showcase_04 import FlextAuthRefactoredSystemShowcaseExample
__all__: tuple[str, ...] = (
    "c", "d", "e", "h", "m", "p", "r", "s", "t", "u", "x",
    "FlextAuthAdvancedFeaturesExample",
    "FlextAuthBasicAuthExample",
    "FlextAuthBasicUsageExample",
    "FlextAuthBasicUsagePortugueseExample",
    "FlextAuthBasicUsageFlows",
    "FlextAuthBasicUsageWorkflow",
    "FlextAuthConfigUsageExample",
    "FlextAuthRefactoredSystemShowcaseExample",
)

_LAZY_IMPORTS = MappingProxyType(
    build_lazy_import_map(
        MappingProxyType({
            ".advanced_features_02": ("FlextAuthAdvancedFeaturesExample",),
            ".basic_auth_05": ("FlextAuthBasicAuthExample",),
            ".basic_usage_01": ("FlextAuthBasicUsageExample",),
            ".basic_usage_07": ("FlextAuthBasicUsagePortugueseExample",),
            ".basic_usage_flows": ("FlextAuthBasicUsageFlows",),
            ".basic_usage_workflow": ("FlextAuthBasicUsageWorkflow",),
            ".flext_config_usage": ("FlextAuthConfigUsageExample",),
            ".refactored_system_showcase_04": ("FlextAuthRefactoredSystemShowcaseExample",),
            "flext_auth": ("c", "d", "e", "h", "m", "p", "r", "s", "t", "u", "x"),
        }),
        alias_groups=MappingProxyType({}),
        sort_keys=False,
    )
)

install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, public_exports=__all__)

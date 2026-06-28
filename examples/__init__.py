# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if _t.TYPE_CHECKING:
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
    from examples.utils import FlextAuthExampleUtilities as FlextAuthExampleUtilities
    from flext_auth import (
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
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".advanced_features_02": ("FlextAuthAdvancedFeaturesExample",),
        ".basic_auth_05": ("FlextAuthBasicAuthExample",),
        ".basic_refactored_usage_06": ("FlextAuthDemo",),
        ".basic_usage_01": ("FlextAuthBasicUsageExample",),
        ".basic_usage_07": ("FlextAuthBasicUsagePortugueseExample",),
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

__all__: list[str] = [
    "FlextAuthAdvancedFeaturesExample",
    "FlextAuthBasicAuthExample",
    "FlextAuthBasicUsageExample",
    "FlextAuthBasicUsagePortugueseExample",
    "FlextAuthComprehensiveDemo",
    "FlextAuthConfigUsageExample",
    "FlextAuthDebugIssuesExample",
    "FlextAuthDemo",
    "FlextAuthExampleUtilities",
    "FlextAuthRefactoredSystemShowcaseExample",
    "FlextAuthSimpleUsageExample",
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
]

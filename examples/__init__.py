# AUTO-GENERATED FILE — Regenerate with: make gen
"""Examples package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.examples.advanced_features_02 import (
        FlextAuthAdvancedFeaturesExample as FlextAuthAdvancedFeaturesExample,
    )
    from flext_auth.examples.basic_auth_05 import (
        FlextAuthBasicAuthExample as FlextAuthBasicAuthExample,
    )
    from flext_auth.examples.basic_refactored_usage_06 import (
        FlextAuthDemo as FlextAuthDemo,
    )
    from flext_auth.examples.basic_usage_01 import (
        FlextAuthBasicUsageExample as FlextAuthBasicUsageExample,
    )
    from flext_auth.examples.basic_usage_07 import (
        FlextAuthBasicUsagePortugueseExample as FlextAuthBasicUsagePortugueseExample,
    )
    from flext_auth.examples.basic_usage_flows import (
        FlextAuthBasicUsageFlows as FlextAuthBasicUsageFlows,
    )
    from flext_auth.examples.basic_usage_workflow import (
        FlextAuthBasicUsageWorkflow as FlextAuthBasicUsageWorkflow,
    )
    from flext_auth.examples.comprehensive_demo_03 import (
        FlextAuthComprehensiveDemo as FlextAuthComprehensiveDemo,
    )
    from flext_auth.examples.debug_auth_issues_09 import (
        FlextAuthDebugIssuesExample as FlextAuthDebugIssuesExample,
    )
    from flext_auth.examples.flext_config_usage import (
        FlextAuthConfigUsageExample as FlextAuthConfigUsageExample,
    )
    from flext_auth.examples.refactored_system_showcase_04 import (
        FlextAuthRefactoredSystemShowcaseExample as FlextAuthRefactoredSystemShowcaseExample,
    )
    from flext_auth.examples.simple_usage_08 import (
        FlextAuthSimpleUsageExample as FlextAuthSimpleUsageExample,
    )
    from flext_auth.examples.utils import (
        FlextAuthExampleUtilities as FlextAuthExampleUtilities,
    )
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
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

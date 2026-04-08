# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Examples package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
_LAZY_IMPORTS = {
    "advanced_features_02": "examples.advanced_features_02",
    "basic_auth_05": "examples.basic_auth_05",
    "basic_refactored_usage_06": "examples.basic_refactored_usage_06",
    "basic_usage_01": "examples.basic_usage_01",
    "basic_usage_07": "examples.basic_usage_07",
    "comprehensive_demo_03": "examples.comprehensive_demo_03",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "debug_auth_issues_09": "examples.debug_auth_issues_09",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "flext_config_usage": "examples.flext_config_usage",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "r": ("flext_core.result", "FlextResult"),
    "refactored_system_showcase_04": "examples.refactored_system_showcase_04",
    "s": ("flext_core.service", "FlextService"),
    "simple_usage_08": "examples.simple_usage_08",
    "utils": "examples.utils",
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "advanced_features_02",
    "basic_auth_05",
    "basic_refactored_usage_06",
    "basic_usage_01",
    "basic_usage_07",
    "comprehensive_demo_03",
    "d",
    "debug_auth_issues_09",
    "e",
    "flext_config_usage",
    "h",
    "r",
    "refactored_system_showcase_04",
    "s",
    "simple_usage_08",
    "utils",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

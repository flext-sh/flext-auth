# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Examples package."""

from __future__ import annotations

import typing as _t

from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import examples.advanced_features_02 as _examples_advanced_features_02

    advanced_features_02 = _examples_advanced_features_02
    import examples.basic_auth_05 as _examples_basic_auth_05

    basic_auth_05 = _examples_basic_auth_05
    import examples.basic_refactored_usage_06 as _examples_basic_refactored_usage_06

    basic_refactored_usage_06 = _examples_basic_refactored_usage_06
    import examples.basic_usage_01 as _examples_basic_usage_01

    basic_usage_01 = _examples_basic_usage_01
    import examples.basic_usage_07 as _examples_basic_usage_07

    basic_usage_07 = _examples_basic_usage_07
    import examples.comprehensive_demo_03 as _examples_comprehensive_demo_03

    comprehensive_demo_03 = _examples_comprehensive_demo_03
    import examples.debug_auth_issues_09 as _examples_debug_auth_issues_09

    debug_auth_issues_09 = _examples_debug_auth_issues_09
    import examples.flext_config_usage as _examples_flext_config_usage

    flext_config_usage = _examples_flext_config_usage
    import examples.refactored_system_showcase_04 as _examples_refactored_system_showcase_04

    refactored_system_showcase_04 = _examples_refactored_system_showcase_04
    import examples.simple_usage_08 as _examples_simple_usage_08

    simple_usage_08 = _examples_simple_usage_08
    import examples.utils as _examples_utils

    utils = _examples_utils

    from flext_core.constants import FlextConstants as c
    from flext_core.decorators import FlextDecorators as d
    from flext_core.exceptions import FlextExceptions as e
    from flext_core.handlers import FlextHandlers as h
    from flext_core.mixins import FlextMixins as x
    from flext_core.models import FlextModels as m
    from flext_core.protocols import FlextProtocols as p
    from flext_core.result import FlextResult as r
    from flext_core.service import FlextService as s
    from flext_core.typings import FlextTypes as t
    from flext_core.utilities import FlextUtilities as u
_LAZY_IMPORTS = {
    "advanced_features_02": "examples.advanced_features_02",
    "basic_auth_05": "examples.basic_auth_05",
    "basic_refactored_usage_06": "examples.basic_refactored_usage_06",
    "basic_usage_01": "examples.basic_usage_01",
    "basic_usage_07": "examples.basic_usage_07",
    "c": ("flext_core.constants", "FlextConstants"),
    "comprehensive_demo_03": "examples.comprehensive_demo_03",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "debug_auth_issues_09": "examples.debug_auth_issues_09",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "flext_config_usage": "examples.flext_config_usage",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "m": ("flext_core.models", "FlextModels"),
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "refactored_system_showcase_04": "examples.refactored_system_showcase_04",
    "s": ("flext_core.service", "FlextService"),
    "simple_usage_08": "examples.simple_usage_08",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "utils": "examples.utils",
    "x": ("flext_core.mixins", "FlextMixins"),
}

__all__ = [
    "advanced_features_02",
    "basic_auth_05",
    "basic_refactored_usage_06",
    "basic_usage_01",
    "basic_usage_07",
    "c",
    "comprehensive_demo_03",
    "d",
    "debug_auth_issues_09",
    "e",
    "flext_config_usage",
    "h",
    "m",
    "p",
    "r",
    "refactored_system_showcase_04",
    "s",
    "simple_usage_08",
    "t",
    "u",
    "utils",
    "x",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

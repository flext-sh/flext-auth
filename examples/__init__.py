# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Examples package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_auth import (
        advanced_features_02,
        basic_auth_05,
        basic_refactored_usage_06,
        basic_usage_01,
        basic_usage_07,
        comprehensive_demo_03,
        debug_auth_issues_09,
        flext_config_usage,
        refactored_system_showcase_04,
        simple_usage_08,
        utils,
    )
    from flext_auth.advanced_features_02 import example_advanced_configuration
    from flext_auth.basic_refactored_usage_06 import FlextAuthDemo
    from flext_auth.basic_usage_01 import example_basic_authentication, logger
    from flext_auth.basic_usage_07 import exemplo_flext_auth
    from flext_auth.comprehensive_demo_03 import demo_complete_auth_workflow
    from flext_auth.debug_auth_issues_09 import debug_password_operations
    from flext_auth.refactored_system_showcase_04 import (
        demonstrate_refactoring_benefits,
    )
    from flext_auth.simple_usage_08 import main
    from flext_auth.utils import basic_example_runner, run_examples
    from flext_core import FlextTypes
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

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextAuthDemo": "flext_auth.basic_refactored_usage_06",
    "advanced_features_02": "flext_auth.advanced_features_02",
    "basic_auth_05": "flext_auth.basic_auth_05",
    "basic_example_runner": "flext_auth.utils",
    "basic_refactored_usage_06": "flext_auth.basic_refactored_usage_06",
    "basic_usage_01": "flext_auth.basic_usage_01",
    "basic_usage_07": "flext_auth.basic_usage_07",
    "c": ("flext_core.constants", "FlextConstants"),
    "comprehensive_demo_03": "flext_auth.comprehensive_demo_03",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "debug_auth_issues_09": "flext_auth.debug_auth_issues_09",
    "debug_password_operations": "flext_auth.debug_auth_issues_09",
    "demo_complete_auth_workflow": "flext_auth.comprehensive_demo_03",
    "demonstrate_refactoring_benefits": "flext_auth.refactored_system_showcase_04",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "example_advanced_configuration": "flext_auth.advanced_features_02",
    "example_basic_authentication": "flext_auth.basic_usage_01",
    "exemplo_flext_auth": "flext_auth.basic_usage_07",
    "flext_config_usage": "flext_auth.flext_config_usage",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "logger": "flext_auth.basic_usage_01",
    "m": ("flext_core.models", "FlextModels"),
    "main": "flext_auth.simple_usage_08",
    "p": ("flext_core.protocols", "FlextProtocols"),
    "r": ("flext_core.result", "FlextResult"),
    "refactored_system_showcase_04": "flext_auth.refactored_system_showcase_04",
    "run_examples": "flext_auth.utils",
    "s": ("flext_core.service", "FlextService"),
    "simple_usage_08": "flext_auth.simple_usage_08",
    "t": ("flext_core.typings", "FlextTypes"),
    "u": ("flext_core.utilities", "FlextUtilities"),
    "utils": "flext_auth.utils",
    "x": ("flext_core.mixins", "FlextMixins"),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

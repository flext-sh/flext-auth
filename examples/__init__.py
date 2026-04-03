# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Examples package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from examples import (
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
    from examples.advanced_features_02 import example_advanced_configuration
    from examples.basic_refactored_usage_06 import FlextAuthDemo
    from examples.basic_usage_01 import example_basic_authentication, logger
    from examples.basic_usage_07 import exemplo_flext_auth
    from examples.comprehensive_demo_03 import demo_complete_auth_workflow
    from examples.debug_auth_issues_09 import debug_password_operations
    from examples.refactored_system_showcase_04 import (
        demonstrate_refactoring_benefits,
    )
    from examples.simple_usage_08 import main
    from examples.utils import basic_example_runner
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
    "FlextAuthDemo": "examples.basic_refactored_usage_06",
    "advanced_features_02": "examples.advanced_features_02",
    "basic_auth_05": "examples.basic_auth_05",
    "basic_example_runner": "examples.utils",
    "basic_refactored_usage_06": "examples.basic_refactored_usage_06",
    "basic_usage_01": "examples.basic_usage_01",
    "basic_usage_07": "examples.basic_usage_07",
    "c": ("flext_core.constants", "FlextConstants"),
    "comprehensive_demo_03": "examples.comprehensive_demo_03",
    "d": ("flext_core.decorators", "FlextDecorators"),
    "debug_auth_issues_09": "examples.debug_auth_issues_09",
    "debug_password_operations": "examples.debug_auth_issues_09",
    "demo_complete_auth_workflow": "examples.comprehensive_demo_03",
    "demonstrate_refactoring_benefits": "examples.refactored_system_showcase_04",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "example_advanced_configuration": "examples.advanced_features_02",
    "example_basic_authentication": "examples.basic_usage_01",
    "exemplo_flext_auth": "examples.basic_usage_07",
    "flext_config_usage": "examples.flext_config_usage",
    "h": ("flext_core.handlers", "FlextHandlers"),
    "logger": "examples.basic_usage_01",
    "m": ("flext_core.models", "FlextModels"),
    "main": "examples.simple_usage_08",
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


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

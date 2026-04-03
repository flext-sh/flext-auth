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
    from examples.advanced_features_02 import (
        example_advanced_configuration,
        example_jwt_operations,
        example_password_security,
        example_role_based_access,
        example_session_management,
        example_token_validation,
    )

    basic_auth_05 = _examples_basic_auth_05
    import examples.basic_refactored_usage_06 as _examples_basic_refactored_usage_06

    basic_refactored_usage_06 = _examples_basic_refactored_usage_06
    import examples.basic_usage_01 as _examples_basic_usage_01
    from examples.basic_refactored_usage_06 import FlextAuthDemo

    basic_usage_01 = _examples_basic_usage_01
    import examples.basic_usage_07 as _examples_basic_usage_07
    from examples.basic_usage_01 import (
        example_advanced_registration,
        example_basic_authentication,
        example_complete_workflow,
        example_direct_auth,
        example_email_validation,
        example_password_operations,
        example_user_lifecycle,
        logger,
    )

    basic_usage_07 = _examples_basic_usage_07
    import examples.comprehensive_demo_03 as _examples_comprehensive_demo_03
    from examples.basic_usage_07 import exemplo_flext_auth

    comprehensive_demo_03 = _examples_comprehensive_demo_03
    import examples.debug_auth_issues_09 as _examples_debug_auth_issues_09
    from examples.comprehensive_demo_03 import (
        demo_complete_auth_workflow,
        demo_error_handling,
        demo_jwt_operations,
        demo_password_operations,
        demo_security_features,
        demo_user_management,
        generate_secure_password,
    )

    debug_auth_issues_09 = _examples_debug_auth_issues_09
    import examples.flext_config_usage as _examples_flext_config_usage
    from examples.debug_auth_issues_09 import (
        debug_authentication_workflow,
        debug_jwt_operations,
        debug_password_operations,
    )

    flext_config_usage = _examples_flext_config_usage
    import examples.refactored_system_showcase_04 as _examples_refactored_system_showcase_04

    refactored_system_showcase_04 = _examples_refactored_system_showcase_04
    import examples.simple_usage_08 as _examples_simple_usage_08
    from examples.refactored_system_showcase_04 import (
        demonstrate_error_handling,
        demonstrate_flext_result_integration,
        demonstrate_quickstart_functionality,
        demonstrate_refactoring_benefits,
        demonstrate_system_architecture,
    )

    simple_usage_08 = _examples_simple_usage_08
    import examples.utils as _examples_utils
    from examples.simple_usage_08 import main

    utils = _examples_utils
    from examples.utils import basic_example_runner
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
    "debug_authentication_workflow": "examples.debug_auth_issues_09",
    "debug_jwt_operations": "examples.debug_auth_issues_09",
    "debug_password_operations": "examples.debug_auth_issues_09",
    "demo_complete_auth_workflow": "examples.comprehensive_demo_03",
    "demo_error_handling": "examples.comprehensive_demo_03",
    "demo_jwt_operations": "examples.comprehensive_demo_03",
    "demo_password_operations": "examples.comprehensive_demo_03",
    "demo_security_features": "examples.comprehensive_demo_03",
    "demo_user_management": "examples.comprehensive_demo_03",
    "demonstrate_error_handling": "examples.refactored_system_showcase_04",
    "demonstrate_flext_result_integration": "examples.refactored_system_showcase_04",
    "demonstrate_quickstart_functionality": "examples.refactored_system_showcase_04",
    "demonstrate_refactoring_benefits": "examples.refactored_system_showcase_04",
    "demonstrate_system_architecture": "examples.refactored_system_showcase_04",
    "e": ("flext_core.exceptions", "FlextExceptions"),
    "example_advanced_configuration": "examples.advanced_features_02",
    "example_advanced_registration": "examples.basic_usage_01",
    "example_basic_authentication": "examples.basic_usage_01",
    "example_complete_workflow": "examples.basic_usage_01",
    "example_direct_auth": "examples.basic_usage_01",
    "example_email_validation": "examples.basic_usage_01",
    "example_jwt_operations": "examples.advanced_features_02",
    "example_password_operations": "examples.basic_usage_01",
    "example_password_security": "examples.advanced_features_02",
    "example_role_based_access": "examples.advanced_features_02",
    "example_session_management": "examples.advanced_features_02",
    "example_token_validation": "examples.advanced_features_02",
    "example_user_lifecycle": "examples.basic_usage_01",
    "exemplo_flext_auth": "examples.basic_usage_07",
    "flext_config_usage": "examples.flext_config_usage",
    "generate_secure_password": "examples.comprehensive_demo_03",
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

__all__ = [
    "FlextAuthDemo",
    "advanced_features_02",
    "basic_auth_05",
    "basic_example_runner",
    "basic_refactored_usage_06",
    "basic_usage_01",
    "basic_usage_07",
    "c",
    "comprehensive_demo_03",
    "d",
    "debug_auth_issues_09",
    "debug_authentication_workflow",
    "debug_jwt_operations",
    "debug_password_operations",
    "demo_complete_auth_workflow",
    "demo_error_handling",
    "demo_jwt_operations",
    "demo_password_operations",
    "demo_security_features",
    "demo_user_management",
    "demonstrate_error_handling",
    "demonstrate_flext_result_integration",
    "demonstrate_quickstart_functionality",
    "demonstrate_refactoring_benefits",
    "demonstrate_system_architecture",
    "e",
    "example_advanced_configuration",
    "example_advanced_registration",
    "example_basic_authentication",
    "example_complete_workflow",
    "example_direct_auth",
    "example_email_validation",
    "example_jwt_operations",
    "example_password_operations",
    "example_password_security",
    "example_role_based_access",
    "example_session_management",
    "example_token_validation",
    "example_user_lifecycle",
    "exemplo_flext_auth",
    "flext_config_usage",
    "generate_secure_password",
    "h",
    "logger",
    "m",
    "main",
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

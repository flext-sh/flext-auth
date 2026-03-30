# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""FLEXT Auth Examples - Demonstration scripts for authentication functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from flext_core import FlextTypes

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
    from examples.advanced_features_02 import (
        example_advanced_configuration,
        example_jwt_operations,
        example_password_security,
        example_role_based_access,
        example_session_management,
        example_token_validation,
    )
    from examples.basic_refactored_usage_06 import FlextAuthDemo
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
    from examples.basic_usage_07 import exemplo_flext_auth
    from examples.comprehensive_demo_03 import (
        demo_complete_auth_workflow,
        demo_error_handling,
        demo_jwt_operations,
        demo_password_operations,
        demo_security_features,
        demo_user_management,
        generate_secure_password,
    )
    from examples.debug_auth_issues_09 import (
        debug_authentication_workflow,
        debug_jwt_operations,
        debug_password_operations,
    )
    from examples.refactored_system_showcase_04 import (
        demonstrate_error_handling,
        demonstrate_flext_result_integration,
        demonstrate_quickstart_functionality,
        demonstrate_refactoring_benefits,
        demonstrate_system_architecture,
    )
    from examples.simple_usage_08 import main
    from examples.utils import basic_example_runner

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "FlextAuthDemo": ["examples.basic_refactored_usage_06", "FlextAuthDemo"],
    "advanced_features_02": ["examples.advanced_features_02", ""],
    "basic_auth_05": ["examples.basic_auth_05", ""],
    "basic_example_runner": ["examples.utils", "basic_example_runner"],
    "basic_refactored_usage_06": ["examples.basic_refactored_usage_06", ""],
    "basic_usage_01": ["examples.basic_usage_01", ""],
    "basic_usage_07": ["examples.basic_usage_07", ""],
    "comprehensive_demo_03": ["examples.comprehensive_demo_03", ""],
    "debug_auth_issues_09": ["examples.debug_auth_issues_09", ""],
    "debug_authentication_workflow": [
        "examples.debug_auth_issues_09",
        "debug_authentication_workflow",
    ],
    "debug_jwt_operations": ["examples.debug_auth_issues_09", "debug_jwt_operations"],
    "debug_password_operations": [
        "examples.debug_auth_issues_09",
        "debug_password_operations",
    ],
    "demo_complete_auth_workflow": [
        "examples.comprehensive_demo_03",
        "demo_complete_auth_workflow",
    ],
    "demo_error_handling": ["examples.comprehensive_demo_03", "demo_error_handling"],
    "demo_jwt_operations": ["examples.comprehensive_demo_03", "demo_jwt_operations"],
    "demo_password_operations": [
        "examples.comprehensive_demo_03",
        "demo_password_operations",
    ],
    "demo_security_features": [
        "examples.comprehensive_demo_03",
        "demo_security_features",
    ],
    "demo_user_management": ["examples.comprehensive_demo_03", "demo_user_management"],
    "demonstrate_error_handling": [
        "examples.refactored_system_showcase_04",
        "demonstrate_error_handling",
    ],
    "demonstrate_flext_result_integration": [
        "examples.refactored_system_showcase_04",
        "demonstrate_flext_result_integration",
    ],
    "demonstrate_quickstart_functionality": [
        "examples.refactored_system_showcase_04",
        "demonstrate_quickstart_functionality",
    ],
    "demonstrate_refactoring_benefits": [
        "examples.refactored_system_showcase_04",
        "demonstrate_refactoring_benefits",
    ],
    "demonstrate_system_architecture": [
        "examples.refactored_system_showcase_04",
        "demonstrate_system_architecture",
    ],
    "example_advanced_configuration": [
        "examples.advanced_features_02",
        "example_advanced_configuration",
    ],
    "example_advanced_registration": [
        "examples.basic_usage_01",
        "example_advanced_registration",
    ],
    "example_basic_authentication": [
        "examples.basic_usage_01",
        "example_basic_authentication",
    ],
    "example_complete_workflow": [
        "examples.basic_usage_01",
        "example_complete_workflow",
    ],
    "example_direct_auth": ["examples.basic_usage_01", "example_direct_auth"],
    "example_email_validation": ["examples.basic_usage_01", "example_email_validation"],
    "example_jwt_operations": [
        "examples.advanced_features_02",
        "example_jwt_operations",
    ],
    "example_password_operations": [
        "examples.basic_usage_01",
        "example_password_operations",
    ],
    "example_password_security": [
        "examples.advanced_features_02",
        "example_password_security",
    ],
    "example_role_based_access": [
        "examples.advanced_features_02",
        "example_role_based_access",
    ],
    "example_session_management": [
        "examples.advanced_features_02",
        "example_session_management",
    ],
    "example_token_validation": [
        "examples.advanced_features_02",
        "example_token_validation",
    ],
    "example_user_lifecycle": ["examples.basic_usage_01", "example_user_lifecycle"],
    "exemplo_flext_auth": ["examples.basic_usage_07", "exemplo_flext_auth"],
    "flext_config_usage": ["examples.flext_config_usage", ""],
    "generate_secure_password": [
        "examples.comprehensive_demo_03",
        "generate_secure_password",
    ],
    "logger": ["examples.basic_usage_01", "logger"],
    "main": ["examples.simple_usage_08", "main"],
    "refactored_system_showcase_04": ["examples.refactored_system_showcase_04", ""],
    "simple_usage_08": ["examples.simple_usage_08", ""],
    "utils": ["examples.utils", ""],
}

__all__ = [
    "FlextAuthDemo",
    "advanced_features_02",
    "basic_auth_05",
    "basic_example_runner",
    "basic_refactored_usage_06",
    "basic_usage_01",
    "basic_usage_07",
    "comprehensive_demo_03",
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
    "logger",
    "main",
    "refactored_system_showcase_04",
    "simple_usage_08",
    "utils",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.

    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.

    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)

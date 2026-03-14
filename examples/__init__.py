# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""FLEXT Auth Examples - Demonstration scripts for authentication functionality.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
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

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "FlextAuthDemo": ("examples.basic_refactored_usage_06", "FlextAuthDemo"),
    "basic_example_runner": ("examples.utils", "basic_example_runner"),
    "debug_authentication_workflow": (
        "examples.debug_auth_issues_09",
        "debug_authentication_workflow",
    ),
    "debug_jwt_operations": ("examples.debug_auth_issues_09", "debug_jwt_operations"),
    "debug_password_operations": (
        "examples.debug_auth_issues_09",
        "debug_password_operations",
    ),
    "demo_complete_auth_workflow": (
        "examples.comprehensive_demo_03",
        "demo_complete_auth_workflow",
    ),
    "demo_error_handling": ("examples.comprehensive_demo_03", "demo_error_handling"),
    "demo_jwt_operations": ("examples.comprehensive_demo_03", "demo_jwt_operations"),
    "demo_password_operations": (
        "examples.comprehensive_demo_03",
        "demo_password_operations",
    ),
    "demo_security_features": (
        "examples.comprehensive_demo_03",
        "demo_security_features",
    ),
    "demo_user_management": ("examples.comprehensive_demo_03", "demo_user_management"),
    "demonstrate_error_handling": (
        "examples.refactored_system_showcase_04",
        "demonstrate_error_handling",
    ),
    "demonstrate_flext_result_integration": (
        "examples.refactored_system_showcase_04",
        "demonstrate_flext_result_integration",
    ),
    "demonstrate_quickstart_functionality": (
        "examples.refactored_system_showcase_04",
        "demonstrate_quickstart_functionality",
    ),
    "demonstrate_refactoring_benefits": (
        "examples.refactored_system_showcase_04",
        "demonstrate_refactoring_benefits",
    ),
    "demonstrate_system_architecture": (
        "examples.refactored_system_showcase_04",
        "demonstrate_system_architecture",
    ),
    "example_advanced_configuration": (
        "examples.advanced_features_02",
        "example_advanced_configuration",
    ),
    "example_advanced_registration": (
        "examples.basic_usage_01",
        "example_advanced_registration",
    ),
    "example_basic_authentication": (
        "examples.basic_usage_01",
        "example_basic_authentication",
    ),
    "example_complete_workflow": (
        "examples.basic_usage_01",
        "example_complete_workflow",
    ),
    "example_direct_auth": ("examples.basic_usage_01", "example_direct_auth"),
    "example_email_validation": ("examples.basic_usage_01", "example_email_validation"),
    "example_jwt_operations": (
        "examples.advanced_features_02",
        "example_jwt_operations",
    ),
    "example_password_operations": (
        "examples.basic_usage_01",
        "example_password_operations",
    ),
    "example_password_security": (
        "examples.advanced_features_02",
        "example_password_security",
    ),
    "example_role_based_access": (
        "examples.advanced_features_02",
        "example_role_based_access",
    ),
    "example_session_management": (
        "examples.advanced_features_02",
        "example_session_management",
    ),
    "example_token_validation": (
        "examples.advanced_features_02",
        "example_token_validation",
    ),
    "example_user_lifecycle": ("examples.basic_usage_01", "example_user_lifecycle"),
    "exemplo_flext_auth": ("examples.basic_usage_07", "exemplo_flext_auth"),
    "generate_secure_password": (
        "examples.comprehensive_demo_03",
        "generate_secure_password",
    ),
    "logger": ("examples.basic_usage_01", "logger"),
    "main": ("examples.simple_usage_08", "main"),
}

__all__ = [
    "FlextAuthDemo",
    "basic_example_runner",
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
    "generate_secure_password",
    "logger",
    "main",
]


def __getattr__(name: str) -> t.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)

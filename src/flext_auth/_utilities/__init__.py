# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
)

if TYPE_CHECKING:
    from flext_auth._utilities._managers.auth_managers_session import (
        FlextAuthSessionManagers as FlextAuthSessionManagers,
    )
    from flext_auth._utilities._managers.rate_limiter import (
        FlextAuthRateLimiterManagers as FlextAuthRateLimiterManagers,
    )
    from flext_auth._utilities._managers.user import (
        FlextAuthUserManagers as FlextAuthUserManagers,
    )
    from flext_auth._utilities._managers.user_create import (
        FlextAuthUserManagerCreate as FlextAuthUserManagerCreate,
    )
    from flext_auth._utilities._managers.user_read import (
        FlextAuthUserManagerRead as FlextAuthUserManagerRead,
    )
    from flext_auth._utilities._managers.user_write import (
        FlextAuthUserManagerWrite as FlextAuthUserManagerWrite,
    )
    from flext_auth._utilities.auth import (
        FlextAuthUtilitiesAuth as FlextAuthUtilitiesAuth,
    )
    from flext_auth._utilities.auth_response import (
        FlextAuthUtilitiesAuthResponse as FlextAuthUtilitiesAuthResponse,
    )
    from flext_auth._utilities.auth_token import (
        FlextAuthUtilitiesAuthToken as FlextAuthUtilitiesAuthToken,
    )
    from flext_auth._utilities.auth_validation import (
        FlextAuthUtilitiesAuthValidation as FlextAuthUtilitiesAuthValidation,
    )
    from flext_auth._utilities.identity_audit import (
        FlextAuthIdentityAudit as FlextAuthIdentityAudit,
    )
    from flext_auth._utilities.managers import (
        FlextAuthUtilitiesManagers as FlextAuthUtilitiesManagers,
    )
_LAZY_IMPORTS = merge_lazy_imports(
    ("._managers",),
    build_lazy_import_map(
        {
            "._managers": ("_managers",),
            "._managers.auth_managers_session": ("FlextAuthSessionManagers",),
            "._managers.rate_limiter": ("FlextAuthRateLimiterManagers",),
            "._managers.user": ("FlextAuthUserManagers",),
            "._managers.user_create": ("FlextAuthUserManagerCreate",),
            "._managers.user_read": ("FlextAuthUserManagerRead",),
            "._managers.user_write": ("FlextAuthUserManagerWrite",),
            ".auth": ("FlextAuthUtilitiesAuth",),
            ".auth_response": ("FlextAuthUtilitiesAuthResponse",),
            ".auth_token": ("FlextAuthUtilitiesAuthToken",),
            ".auth_validation": ("FlextAuthUtilitiesAuthValidation",),
            ".identity_audit": ("FlextAuthIdentityAudit",),
            ".managers": ("FlextAuthUtilitiesManagers",),
        },
    ),
    exclude_names=(
        "cleanup_submodule_namespace",
        "install_lazy_exports",
        "lazy_getattr",
        "logger",
        "merge_lazy_imports",
        "output",
        "output_reporting",
        "pytest_addoption",
        "pytest_collect_file",
        "pytest_collection_modifyitems",
        "pytest_configure",
        "pytest_runtest_setup",
        "pytest_runtest_teardown",
        "pytest_sessionfinish",
        "pytest_sessionstart",
        "pytest_terminal_summary",
        "pytest_warning_recorded",
    ),
    module_name=__name__,
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Utilities package."""

from __future__ import annotations

from flext_core.lazy import (
    build_lazy_import_map,
    install_lazy_exports,
    merge_lazy_imports,
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
            "._managers.user_extras": ("FlextAuthUserIdentityExtras",),
            "._managers.user_read": ("FlextAuthUserManagerRead",),
            "._managers.user_write": ("FlextAuthUserManagerWrite",),
            ".auth": ("FlextAuthUtilitiesAuth",),
            ".auth_response": ("FlextAuthUtilitiesAuthResponse",),
            ".auth_token": ("FlextAuthUtilitiesAuthToken",),
            ".auth_validation": ("FlextAuthUtilitiesAuthValidation",),
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

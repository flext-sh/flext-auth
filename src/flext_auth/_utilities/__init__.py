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
            "._managers.auth_managers_session": ("FlextAuthSessionManagers",),
            "._managers.rate_limiter": ("FlextAuthRateLimiterManagers",),
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
    ),
    module_name=__name__,
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)

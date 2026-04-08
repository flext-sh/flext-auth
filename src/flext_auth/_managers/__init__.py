# AUTO-GENERATED FILE — Regenerate with: make gen
"""Managers package."""

from __future__ import annotations

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".auth_managers_session": ("FlextAuthSessionManagers",),
        ".rate_limiter": ("FlextAuthRateLimiterManagers",),
    },
)


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)

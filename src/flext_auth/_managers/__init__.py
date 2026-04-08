# AUTO-GENERATED FILE — Regenerate with: make gen
"""Managers package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextAuthRateLimiterManagers": ".rate_limiter",
    "FlextAuthSessionManagers": ".auth_managers_session",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)

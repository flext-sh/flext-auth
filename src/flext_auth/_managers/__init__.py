# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Managers package."""

from __future__ import annotations

from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    "FlextAuthRateLimiterManagers": (
        "flext_auth._managers.rate_limiter",
        "FlextAuthRateLimiterManagers",
    ),
    "FlextAuthSessionManagers": (
        "flext_auth._managers.auth_managers_session",
        "FlextAuthSessionManagers",
    ),
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, publish_all=False)

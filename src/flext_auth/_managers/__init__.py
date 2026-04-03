# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Managers package."""

from __future__ import annotations

import typing as _t

from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers
from flext_core.lazy import install_lazy_exports

if _t.TYPE_CHECKING:
    import flext_auth._managers.auth_managers_session as _flext_auth__managers_auth_managers_session

    auth_managers_session = _flext_auth__managers_auth_managers_session
    import flext_auth._managers.rate_limiter as _flext_auth__managers_rate_limiter

    rate_limiter = _flext_auth__managers_rate_limiter

    _ = (
        FlextAuthRateLimiterManagers,
        FlextAuthSessionManagers,
        auth_managers_session,
        rate_limiter,
    )
_LAZY_IMPORTS = {
    "FlextAuthRateLimiterManagers": "flext_auth._managers.rate_limiter",
    "FlextAuthSessionManagers": "flext_auth._managers.auth_managers_session",
    "auth_managers_session": "flext_auth._managers.auth_managers_session",
    "rate_limiter": "flext_auth._managers.rate_limiter",
}

__all__ = [
    "FlextAuthRateLimiterManagers",
    "FlextAuthSessionManagers",
    "auth_managers_session",
    "rate_limiter",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

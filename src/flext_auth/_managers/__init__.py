# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Managers package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_auth._managers import auth_managers_session, rate_limiter
    from flext_auth._managers.auth_managers_session import FlextAuthSessionManagers
    from flext_auth._managers.rate_limiter import FlextAuthRateLimiterManagers
    from flext_core import FlextTypes

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "FlextAuthRateLimiterManagers": "flext_auth._managers.rate_limiter",
    "FlextAuthSessionManagers": "flext_auth._managers.auth_managers_session",
    "auth_managers_session": "flext_auth._managers.auth_managers_session",
    "rate_limiter": "flext_auth._managers.rate_limiter",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

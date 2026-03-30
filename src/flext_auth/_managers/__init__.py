# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
#
"""Managers package."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._managers.auth_managers_session import *
    from flext_auth._managers.rate_limiter import *

_LAZY_IMPORTS: Mapping[str, str | Sequence[str]] = {
    "FlextAuthRateLimiterManagers": "flext_auth._managers.rate_limiter",
    "FlextAuthSessionManagers": "flext_auth._managers.auth_managers_session",
    "auth_managers_session": "flext_auth._managers.auth_managers_session",
    "rate_limiter": "flext_auth._managers.rate_limiter",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

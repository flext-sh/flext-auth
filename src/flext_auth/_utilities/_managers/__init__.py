# AUTO-GENERATED FILE — Regenerate with: make gen
"""Managers package."""

from __future__ import annotations

from .auth_managers_session import FlextAuthSessionManagers as FlextAuthSessionManagers
from .rate_limiter import FlextAuthRateLimiterManagers as FlextAuthRateLimiterManagers
from .user import FlextAuthUserManagers as FlextAuthUserManagers
from .user_create import FlextAuthUserManagerCreate as FlextAuthUserManagerCreate
from .user_read import FlextAuthUserManagerRead as FlextAuthUserManagerRead
from .user_write import FlextAuthUserManagerWrite as FlextAuthUserManagerWrite

__all__: tuple[str, ...] = (
    "FlextAuthRateLimiterManagers",
    "FlextAuthSessionManagers",
    "FlextAuthUserManagerCreate",
    "FlextAuthUserManagerRead",
    "FlextAuthUserManagerWrite",
    "FlextAuthUserManagers",
)

"""Backward-compat domain_entities facade for flext-auth.

Re-exports authentication domain models under the legacy module name to
maintain compatibility with existing tests and examples.
"""

from __future__ import annotations

from flext_auth.models import (
    FlextAuthModels,
    FlextAuthPermission,
    FlextAuthRole,
    FlextAuthSession,
    FlextAuthUser,
)

__all__ = [
    "FlextAuthModels",
    "FlextAuthPermission",
    "FlextAuthRole",
    "FlextAuthSession",
    "FlextAuthUser",
]

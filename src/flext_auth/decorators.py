"""FLEXT Auth Decorators - thin public module.

This module re-exports the public decorator APIs from `flext_auth.auth_decorators`
so the file stays small and maintainable while tests enforce size limits.
"""

from __future__ import annotations

from flext_auth.auth_decorators import (
    FlextAuthDecoratorConfig,
    flext_auth_permission_required,
    flext_auth_required,
    flext_auth_role_required,
)

__all__: list[str] = [
    "FlextAuthDecoratorConfig",
    "flext_auth_permission_required",
    "flext_auth_required",
    "flext_auth_role_required",
]

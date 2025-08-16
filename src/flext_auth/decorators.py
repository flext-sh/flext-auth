"""FLEXT Auth Decorators - thin public module.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

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

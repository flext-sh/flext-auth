"""FLEXT Auth Utilities - DRY principle centralization for common functions.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

"""

from __future__ import annotations

from flext_auth.domain_entities import FlextUser


def convert_user_to_dict(user: FlextUser) -> dict[str, object]:
    """Convert FlextUser entity to dictionary format - DRY principle.

    SOLID REFACTORING: Eliminates 23 lines of code duplication between __init__.py
    and helpers.py using DRY principle. This function centralizes user-to-dict
    conversion logic in one place.

    Args:
      user: FlextUser entity to convert
    Returns:
      Dictionary representation of user data

    """
    return {
        "id": user.id,
        "username": user.username,
        "email": user.email,
        "role": (user.role.value if hasattr(user.role, "value") else str(user.role)),
        "status": (
            user.status.value if hasattr(user.status, "value") else str(user.status)
        ),
    }

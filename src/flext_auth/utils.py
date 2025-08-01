"""Utility functions for FLEXT Auth - DRY principle centralization.

SOLID REFACTORING: This module centralizes common utility functions to eliminate
code duplication across __init__.py and helpers.py using DRY principle.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from flext_auth.domain.entities import FlextUser


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

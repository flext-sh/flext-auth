"""FLEXT Auth Types - Type definitions and Union types for authentication system.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module defines all type aliases and Union types used throughout
the authentication system to avoid circular imports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:

    # Union types for repository flexibility - prevents circular imports
    UserRepositoryType = (
        "InMemoryUserRepository" | "SimplePostgreSQLUserRepository"
    )
    SessionRepositoryType = (
        "InMemorySessionRepository" | "SimplePostgreSQLSessionRepository"
    )
else:
    # Runtime fallback - use string forward references
    UserRepositoryType = "InMemoryUserRepository | SimplePostgreSQLUserRepository"
    SessionRepositoryType = (
        "InMemorySessionRepository | SimplePostgreSQLSessionRepository"
    )

__all__ = [
    "SessionRepositoryType",
    "UserRepositoryType",
]

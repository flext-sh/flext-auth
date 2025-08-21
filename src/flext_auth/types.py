"""FLEXT Auth Types - Type definitions and Union types for authentication system.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

This module defines all type aliases and Union types used throughout
the authentication system to avoid circular imports.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Union

if TYPE_CHECKING:
    from flext_auth.repositories_simple import (
        SimplePostgreSQLSessionRepository,
        SimplePostgreSQLUserRepository,
    )
    from flext_auth.session import InMemorySessionRepository
    from flext_auth.user import InMemoryUserRepository

    # Union types for repository flexibility - prevents circular imports
    UserRepositoryType = Union[
        "InMemoryUserRepository", "SimplePostgreSQLUserRepository"
    ]
    SessionRepositoryType = Union[
        "InMemorySessionRepository", "SimplePostgreSQLSessionRepository"
    ]
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

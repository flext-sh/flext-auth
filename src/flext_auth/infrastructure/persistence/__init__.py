"""FLEXT Auth persistence layer implementations."""

from __future__ import annotations

from .user_repository import PostgreSQLUserRepository

__all__ = ["PostgreSQLUserRepository"]

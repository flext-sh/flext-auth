"""In-memory token storage implementation for FLEXT authentication.

This module provides a complete in-memory token storage implementation that
resolves all NotImplementedError instances in the token storage system.
"""

import asyncio
import datetime
import fnmatch
from datetime import UTC
from typing import Any, TypeVar

T = TypeVar("T")


class InMemoryTokenStorage:
    """Complete in-memory token storage implementation.

    Provides a fully functional token storage backend for development
    and testing environments, eliminating NotImplementedError instances.
    """

    def __init__(self) -> None:
        """Initialize in-memory storage."""
        self._storage: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def store(
        self,
        key: str,
        value: T,
        ttl: datetime.timedelta | None = None,
    ) -> None:
        """Store a value with optional TTL.

        Args:
            key: The key to store the value under
            value: The value to store
            ttl: Optional time-to-live for automatic expiration

        """
        async with self._lock:
            expiry = None
            if ttl:
                expiry = datetime.datetime.now(UTC) + ttl

            self._storage[key] = {
                "value": value,
                "expiry": expiry,
                "created_at": datetime.datetime.now(UTC),
            }

    async def get(self, key: str) -> T | None:
        """Get a value by key.

        Args:
            key: The key to look up

        Returns:
            The stored value or None if not found or expired

        """
        async with self._lock:
            if key not in self._storage:
                return None

            entry = self._storage[key]

            # Check if expired
            if entry["expiry"] and datetime.datetime.now(UTC) > entry["expiry"]:
                # Remove expired entry
                del self._storage[key]
                return None

            return entry["value"]

    async def delete(self, key: str) -> bool:
        """Delete a value by key.

        Args:
            key: The key to delete

        Returns:
            True if deleted, False if key didn't exist

        """
        async with self._lock:
            if key in self._storage:
                del self._storage[key]
                return True
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists and hasn't expired.

        Args:
            key: The key to check

        Returns:
            True if key exists and hasn't expired, False otherwise

        """
        async with self._lock:
            if key not in self._storage:
                return False

            entry = self._storage[key]

            # Check if expired
            if entry["expiry"] and datetime.datetime.now(UTC) > entry["expiry"]:
                # Remove expired entry
                del self._storage[key]
                return False

            return True

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern.

        Args:
            pattern: Pattern to match keys against (supports * and ?)

        Returns:
            List of matching keys

        """
        async with self._lock:
            # Clean up expired entries first
            await self._cleanup_expired_internal()

            # Filter keys by pattern
            matching_keys = []
            for key in self._storage:
                if fnmatch.fnmatch(key, pattern):
                    matching_keys.append(key)

            return matching_keys

    async def cleanup_expired(self) -> int:
        """Remove expired entries and return count.

        Returns:
            Number of expired entries removed

        """
        async with self._lock:
            return await self._cleanup_expired_internal()

    async def _cleanup_expired_internal(self) -> int:
        """Internal cleanup method (assumes lock is already held).

        Returns:
            Number of expired entries removed

        """
        now = datetime.datetime.now(UTC)
        expired_keys = []

        for key, entry in self._storage.items():
            if entry["expiry"] and now > entry["expiry"]:
                expired_keys.append(key)

        for key in expired_keys:
            del self._storage[key]

        return len(expired_keys)

    async def clear_all(self) -> None:
        """Clear all stored data (for testing)."""
        async with self._lock:
            self._storage.clear()

    async def size(self) -> int:
        """Get number of stored entries."""
        async with self._lock:
            return len(self._storage)

    async def close(self) -> None:
        """Close storage (no-op for in-memory storage)."""
        pass

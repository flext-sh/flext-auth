"""In-memory token storage implementation for FLEXT authentication.

This module provides a complete in-memory token storage implementation that
resolves all NotImplementedError instances in the token storage system.
"""

import asyncio
import fnmatch
from datetime import UTC
from datetime import datetime
from typing import Any
from typing import TypeVar

T = TypeVar("T")


class InMemoryTokenStorage:
    """Complete in-memory token storage implementation.

    Provides a fully functional token storage backend for development
    and testing environments, eliminating NotImplementedError instances.
    """

    def __init__(self) -> None:
        self._storage: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def store(
        self, key: str, value: T, ttl: datetime.timedelta | None = None,
    ) -> None:
        """Store a value with optional TTL expiration.

        Args:
            key: Storage key for the value.
            value: Value to store.
            ttl: Optional time-to-live for expiration.

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
        """Retrieve a value by key, removing if expired.

        Args:
            key: Storage key to retrieve.

        Returns:
            Stored value if found and not expired, None otherwise.

        """
        async with self._lock:
            if key not in self._storage:
                return None

            entry = self._storage[key]

            # Check if expired:
            if entry["expiry"] and datetime.datetime.now(UTC) > entry["expiry"]:
                # Remove expired entry
                del self._storage[key]
                return None

            return entry["value"]

    async def delete(self, key: str) -> bool:
        """Delete a stored value by key.

        Args:
            key: Storage key to delete.

        Returns:
            True if key was found and deleted, False otherwise.

        """
        async with self._lock:
            if key in self._storage:
                del self._storage[key]
                return True
            return False

    async def exists(self, key: str) -> bool:
        """Check if a key exists and is not expired.

        Args:
            key: Storage key to check.

        Returns:
            True if key exists and is not expired, False otherwise.

        """
        async with self._lock:
            if key not in self._storage:
                return False

            entry = self._storage[key]

            # Check if expired:
            if entry["expiry"] and datetime.datetime.now(UTC) > entry["expiry"]:
                # Remove expired entry
                del self._storage[key]
                return False

            return True

    async def keys(self, pattern: str) -> list[str]:
        """Get all keys matching a pattern.

        Args:
            pattern: Wildcard pattern to match keys against.

        Returns:
            List of keys matching the pattern.

        """
        async with self._lock:
            # Clean up expired entries first
            await self._cleanup_expired_internal()

            # Filter keys by pattern using list comprehension
            return [key for key in self._storage if fnmatch.fnmatch(key, pattern)]

    async def cleanup_expired(self) -> int:
        """Remove all expired entries from storage.

        Returns:
            Number of expired entries that were removed.

        """
        async with self._lock:
            return await self._cleanup_expired_internal()

    async def _cleanup_expired_internal(self) -> int:
        now = datetime.datetime.now(UTC)
        expired_keys = []

        for key, entry in self._storage.items():
            if entry["expiry"] and now > entry["expiry"]:
                expired_keys.append(key)

        for key in expired_keys:
            del self._storage[key]

        return len(expired_keys)

    async def clear_all(self) -> None:
        """Clear all stored entries."""
        async with self._lock:
            self._storage.clear()

    async def size(self) -> int:
        """Get the number of stored entries.

        Returns:
            Number of entries currently in storage.

        """
        async with self._lock:
            return len(self._storage)

    async def close(self) -> None:
        """Close storage - no-op for in-memory storage."""

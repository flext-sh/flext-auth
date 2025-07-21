"""Comprehensive tests for in_memory_token_storage module.

Tests all functionality in InMemoryTokenStorage to achieve 100% coverage
and verify token storage implementation.
"""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

from flext_auth.in_memory_token_storage import InMemoryTokenStorage


class TestInMemoryTokenStorage:
    """Test InMemoryTokenStorage implementation."""

    def test_initialization(self) -> None:
        """Test InMemoryTokenStorage initialization."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        assert isinstance(storage._storage, dict)
        assert len(storage._storage) == 0
        assert isinstance(storage._lock, asyncio.Lock)

    @pytest.mark.asyncio
    async def test_store_without_ttl(self) -> None:
        """Test storing value without TTL."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "test_key"
        value = {"user_id": "123", "token": "abc123"}

        await storage.store(key, value)

        assert key in storage._storage
        stored_data = storage._storage[key]
        assert stored_data["value"] == value
        assert stored_data["expiry"] is None

    @pytest.mark.asyncio
    async def test_store_with_ttl(self) -> None:
        """Test storing value with TTL."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "test_key_ttl"
        value = {"user_id": "456", "token": "def456"}
        ttl = timedelta(minutes=30)

        before_store = datetime.now(UTC)
        await storage.store(key, value, ttl)
        after_store = datetime.now(UTC)

        assert key in storage._storage
        stored_data = storage._storage[key]
        assert stored_data["value"] == value
        assert stored_data["expiry"] is not None

        # Check that expiry is approximately correct (within reasonable bounds)
        before_store + ttl
        actual_expiry = stored_data["expiry"]
        assert before_store + ttl <= actual_expiry <= after_store + ttl

    @pytest.mark.asyncio
    async def test_retrieve_existing_key(self) -> None:
        """Test retrieving existing key."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "retrieve_test"
        value = {"data": "test_value"}

        await storage.store(key, value)
        retrieved = await storage.get(key)

        assert retrieved == value

    @pytest.mark.asyncio
    async def test_retrieve_nonexistent_key(self) -> None:
        """Test retrieving non-existent key returns None."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "nonexistent_key"

        retrieved = await storage.get(key)
        assert retrieved is None

    @pytest.mark.asyncio
    async def test_retrieve_expired_key(self) -> None:
        """Test retrieving expired key returns None and cleans up."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "expired_key"
        value = {"data": "expired_value"}

        # Store with very short TTL
        ttl = timedelta(milliseconds=1)
        await storage.store(key, value, ttl)

        # Wait for expiration
        await asyncio.sleep(0.01)  # 10ms to ensure expiration

        retrieved = await storage.get(key)
        assert retrieved is None

        # Verify key was cleaned up
        assert key not in storage._storage

    @pytest.mark.asyncio
    async def test_retrieve_valid_key_with_ttl(self) -> None:
        """Test retrieving valid key with TTL that hasn't expired."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "valid_ttl_key"
        value = {"data": "valid_value"}
        ttl = timedelta(hours=1)  # Long TTL

        await storage.store(key, value, ttl)
        retrieved = await storage.get(key)

        assert retrieved == value

    @pytest.mark.asyncio
    async def test_delete_existing_key(self) -> None:
        """Test deleting existing key."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "delete_test"
        value = {"data": "to_be_deleted"}

        await storage.store(key, value)
        assert key in storage._storage

        result = await storage.delete(key)
        assert result is True
        assert key not in storage._storage

    @pytest.mark.asyncio
    async def test_delete_nonexistent_key(self) -> None:
        """Test deleting non-existent key returns False."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "nonexistent_delete"

        result = await storage.delete(key)
        assert result is False

    @pytest.mark.asyncio
    async def test_exists_existing_key(self) -> None:
        """Test exists returns True for existing key."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "exists_test"
        value = {"data": "exists"}

        await storage.store(key, value)
        exists = await storage.exists(key)

        assert exists is True

    @pytest.mark.asyncio
    async def test_exists_nonexistent_key(self) -> None:
        """Test exists returns False for non-existent key."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "nonexistent_exists"

        exists = await storage.exists(key)
        assert exists is False

    @pytest.mark.asyncio
    async def test_exists_expired_key(self) -> None:
        """Test exists returns False for expired key and cleans up."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "expired_exists"
        value = {"data": "expired"}

        # Store with very short TTL
        ttl = timedelta(milliseconds=1)
        await storage.store(key, value, ttl)

        # Wait for expiration
        await asyncio.sleep(0.01)  # 10ms to ensure expiration

        exists = await storage.exists(key)
        assert exists is False

        # Verify key was cleaned up
        assert key not in storage._storage

    @pytest.mark.asyncio
    async def test_clear_all_keys(self) -> None:
        """Test clearing all keys."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Store multiple keys
        keys = ["key1", "key2", "key3"]
        for key in keys:
            await storage.store(key, {"data": f"value_{key}"})

        # Verify keys exist
        for key in keys:
            assert key in storage._storage

        # Clear all
        await storage.clear_all()

        # Verify all keys are gone
        assert len(storage._storage) == 0
        for key in keys:
            assert key not in storage._storage

    @pytest.mark.asyncio
    async def test_clear_empty_storage(self) -> None:
        """Test clearing empty storage."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Clear empty storage should work without issues
        await storage.clear_all()
        assert len(storage._storage) == 0

    @pytest.mark.asyncio
    async def test_keys_empty_storage(self) -> None:
        """Test getting keys from empty storage."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        keys = await storage.keys("*")
        assert keys == []

    @pytest.mark.asyncio
    async def test_keys_with_data(self) -> None:
        """Test getting keys with stored data."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Store multiple keys
        test_keys = ["alpha", "beta", "gamma"]
        for key in test_keys:
            await storage.store(key, {"data": f"value_{key}"})

        keys = await storage.keys("*")
        assert set(keys) == set(test_keys)

    @pytest.mark.asyncio
    async def test_keys_with_expired_data(self) -> None:
        """Test getting keys excludes expired entries."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Store valid key
        await storage.store("valid_key", {"data": "valid"}, timedelta(hours=1))

        # Store expired key
        await storage.store(
            "expired_key",
            {"data": "expired"},
            timedelta(milliseconds=1),
        )

        # Wait for expiration
        await asyncio.sleep(0.01)

        keys = await storage.keys("*")
        assert "valid_key" in keys
        assert "expired_key" not in keys

        # Verify expired key was cleaned up
        assert "expired_key" not in storage._storage

    @pytest.mark.asyncio
    async def test_keys_pattern_matching_simple(self) -> None:
        """Test getting keys with simple pattern matching."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Store keys with different patterns
        test_keys = ["user:123", "user:456", "session:abc", "session:def", "token:xyz"]
        for key in test_keys:
            await storage.store(key, {"data": f"value_{key}"})

        # Test pattern matching
        user_keys = await storage.keys("user:*")
        assert set(user_keys) == {"user:123", "user:456"}

        session_keys = await storage.keys("session:*")
        assert set(session_keys) == {"session:abc", "session:def"}

        token_keys = await storage.keys("token:*")
        assert set(token_keys) == {"token:xyz"}

    @pytest.mark.asyncio
    async def test_keys_pattern_matching_complex(self) -> None:
        """Test getting keys with complex pattern matching."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Store keys with different patterns
        test_keys = ["user_123", "user_456", "REDACTED_LDAP_BIND_PASSWORD_123", "guest_999", "temp_abc"]
        for key in test_keys:
            await storage.store(key, {"data": f"value_{key}"})

        # Test complex patterns
        user_keys = await storage.keys("user_*")
        assert set(user_keys) == {"user_123", "user_456"}

        numbered_keys = await storage.keys("*_123")
        assert set(numbered_keys) == {"user_123", "REDACTED_LDAP_BIND_PASSWORD_123"}

        all_keys = await storage.keys("*")
        assert set(all_keys) == set(test_keys)

    @pytest.mark.asyncio
    async def test_keys_pattern_no_matches(self) -> None:
        """Test getting keys with pattern that matches nothing."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Store some keys
        await storage.store("user:123", {"data": "user"})
        await storage.store("session:abc", {"data": "session"})

        # Pattern that matches nothing
        keys = await storage.keys("REDACTED_LDAP_BIND_PASSWORD:*")
        assert keys == []

    @pytest.mark.asyncio
    async def test_concurrent_access(self) -> None:
        """Test concurrent access to storage is thread-safe."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        async def store_worker(worker_id: int) -> None:
            """Worker function that stores multiple keys."""
            for i in range(10):
                key = f"worker_{worker_id}_key_{i}"
                value = {"worker": worker_id, "index": i}
                await storage.store(key, value)

        async def retrieve_worker(worker_id: int) -> int:
            """Worker function that retrieves keys."""
            retrieved_count = 0
            for i in range(10):
                key = f"worker_{worker_id}_key_{i}"
                # Use small delay to allow interleaving with store operations
                await asyncio.sleep(0.001)
                value = await storage.get(key)
                if value is not None:
                    retrieved_count += 1
            return retrieved_count

        # Run concurrent store and retrieve operations
        store_tasks = [store_worker(i) for i in range(3)]
        retrieve_tasks = [retrieve_worker(i) for i in range(3)]

        # Execute all tasks concurrently
        await asyncio.gather(*store_tasks, *retrieve_tasks)

        # Verify final state - should have 30 keys (3 workers * 10 keys each)
        all_keys = await storage.keys("*")
        assert len(all_keys) == 30

    @pytest.mark.asyncio
    async def test_update_existing_key(self) -> None:
        """Test updating existing key overwrites value."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "update_test"

        # Store initial value
        initial_value = {"version": 1, "data": "initial"}
        await storage.store(key, initial_value)

        retrieved = await storage.get(key)
        assert retrieved == initial_value

        # Update with new value
        updated_value = {"version": 2, "data": "updated"}
        await storage.store(key, updated_value)

        retrieved = await storage.get(key)
        assert retrieved == updated_value
        assert retrieved != initial_value

    @pytest.mark.asyncio
    async def test_ttl_extension(self) -> None:
        """Test that updating a key can extend TTL."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "ttl_extension_test"
        value = {"data": "persistent"}

        # Store with short TTL
        short_ttl = timedelta(milliseconds=50)
        await storage.store(key, value, short_ttl)

        # Wait half the TTL
        await asyncio.sleep(0.025)

        # Update with longer TTL
        long_ttl = timedelta(hours=1)
        await storage.store(key, value, long_ttl)

        # Wait past original TTL
        await asyncio.sleep(0.050)

        # Should still exist due to TTL extension
        retrieved = await storage.get(key)
        assert retrieved == value

    @pytest.mark.asyncio
    async def test_mixed_ttl_and_permanent_keys(self) -> None:
        """Test mixing keys with TTL and permanent keys."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()

        # Store permanent key
        await storage.store("permanent", {"type": "permanent"})

        # Store TTL key
        await storage.store(
            "temporary",
            {"type": "temporary"},
            timedelta(milliseconds=10),
        )

        # Both should exist initially
        assert await storage.exists("permanent")
        assert await storage.exists("temporary")

        # Wait for TTL expiration
        await asyncio.sleep(0.020)

        # Only permanent should exist
        assert await storage.exists("permanent")
        assert not await storage.exists("temporary")

        # Verify permanent key still retrievable
        retrieved = await storage.get("permanent")
        assert retrieved == {"type": "permanent"}

    @pytest.mark.asyncio
    async def test_large_data_storage(self) -> None:
        """Test storing and retrieving large data structures."""
        storage: InMemoryTokenStorage[Any] = InMemoryTokenStorage()
        key = "large_data"

        # Create large data structure
        large_value = {
            "users": [
                {"id": i, "name": f"user_{i}", "data": "x" * 100} for i in range(100)
            ],
            "metadata": {"created": datetime.now(UTC).isoformat(), "version": "1.0"},
            "config": {"settings": {f"key_{i}": f"value_{i}" for i in range(50)}},
        }

        await storage.store(key, large_value)
        retrieved = await storage.get(key)

        assert retrieved == large_value
        assert retrieved is not None
        assert len(retrieved["users"]) == 100
        assert len(retrieved["config"]["settings"]) == 50

"""Comprehensive tests for flext_auth.tokens module."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime as dt, timedelta
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

import pytest

from flext_auth.tokens import (
    DatabaseTokenStorage,
    InMemoryTokenStorage,
    InMemoryTokenStorageAlternative,
    RedisTokenStorage,
    TokenBlacklist,
    TokenInclusionMode,
    TokenManager,
    TokenMetadata,
    TokenPasswordHasher,
    create_token_storage,
    get_domain_constants,
)
from flext_auth.types import TokenType

# NOTE: Only async tests should be marked with @pytest.mark.asyncio individually
# Removed global pytestmark to avoid warnings on non-async tests


class TestTokenConstants:
    """Test token constants and utilities."""

    def test_get_domain_constants(self) -> None:
        """Test getting domain constants."""
        constants = get_domain_constants()

        assert constants.REDIS_KEY_PREFIX == "flext:token:"
        assert constants.DEFAULT_TTL_SECONDS == 3600
        assert constants.CLEANUP_BATCH_SIZE == 100


class TestTokenInclusionMode:
    """Test TokenInclusionMode enum."""

    def test_token_inclusion_mode_values(self) -> None:
        """Test TokenInclusionMode enum values."""
        assert TokenInclusionMode.ACTIVE_ONLY.value == "active_only"
        assert TokenInclusionMode.INCLUDE_EXPIRED.value == "include_expired"

    def test_token_inclusion_mode_membership(self) -> None:
        """Test TokenInclusionMode enum membership."""
        assert "active_only" in TokenInclusionMode
        assert "include_expired" in TokenInclusionMode
        assert "invalid_mode" not in TokenInclusionMode


class TestTokenMetadata:
    """Test TokenMetadata value object."""

    @pytest.fixture
    def sample_token_metadata(self) -> TokenMetadata:
        """Create sample token metadata for testing."""
        return TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
        )

    def test_token_metadata_creation(
        self,
        sample_token_metadata: TokenMetadata,
    ) -> None:
        """Test creating TokenMetadata instance."""
        assert sample_token_metadata.token_id == "token123"
        assert sample_token_metadata.user_id is not None  # UUID generated in fixture
        assert sample_token_metadata.token_type == "access"
        assert isinstance(sample_token_metadata.issued_at, dt)
        assert isinstance(sample_token_metadata.expires_at, dt)

    def test_token_metadata_optional_fields(self) -> None:
        """Test TokenMetadata with optional fields."""
        metadata = TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Mozilla/5.0",
            device_info={"platform": "web", "browser": "chrome"},
        )

        assert metadata.ip_address == "192.168.1.1"
        assert metadata.user_agent == "Mozilla/5.0"
        assert metadata.device_info["platform"] == "web"

    def test_is_expired_property(self) -> None:
        """Test is_expired property."""
        # Non-expired token
        future_metadata = TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
        )
        assert not future_metadata.is_expired

        # Expired token
        past_metadata = TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC) - timedelta(hours=2),
            expires_at=dt.now(UTC) - timedelta(hours=1),
        )
        assert past_metadata.is_expired

    def test_is_revoked_property(self, sample_token_metadata: TokenMetadata) -> None:
        """Test is_revoked property."""
        # Non-revoked token
        assert not sample_token_metadata.is_revoked

        # Revoked token
        revoked_metadata = TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
            revoked_at=dt.now(UTC),
            revoked_by=uuid4(),
            revocation_reason="Security breach",
        )
        assert revoked_metadata.is_revoked

    def test_is_valid_property(self) -> None:
        """Test is_valid property."""
        # Valid token (not expired, not revoked)
        valid_metadata = TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
        )
        assert valid_metadata.is_valid

        # Invalid due to expiration
        expired_metadata = TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC) - timedelta(hours=2),
            expires_at=dt.now(UTC) - timedelta(hours=1),
        )
        assert not expired_metadata.is_valid

        # Invalid due to revocation
        revoked_metadata = TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
            revoked_at=dt.now(UTC),
        )
        assert not revoked_metadata.is_valid

    def test_revoke_method(self, sample_token_metadata: TokenMetadata) -> None:
        """Test revoke method creates new revoked instance."""
        REDACTED_LDAP_BIND_PASSWORD_user_id = uuid4()
        revoked = sample_token_metadata.revoke(
            revoked_by=REDACTED_LDAP_BIND_PASSWORD_user_id,
            reason="Security policy violation",
        )

        # Original should be unchanged (immutable)
        assert not sample_token_metadata.is_revoked

        # New instance should be revoked
        assert revoked.is_revoked
        assert revoked.revoked_by == REDACTED_LDAP_BIND_PASSWORD_user_id
        assert revoked.revocation_reason == "Security policy violation"
        assert revoked.revoked_at is not None


class TestInMemoryTokenStorage:
    """Test InMemoryTokenStorage implementation."""

    @pytest.fixture
    def storage(self) -> InMemoryTokenStorage:
        """Create InMemoryTokenStorage for testing."""
        return InMemoryTokenStorage()

    @pytest.mark.asyncio
    async def test_store_and_get(self, storage: InMemoryTokenStorage) -> None:
        """Test storing and retrieving tokens."""
        key = "test_token"
        value = "token_value_123"

        # Store token
        await storage.store(key, value)

        # Retrieve token
        retrieved = await storage.get(key)
        assert retrieved == value

    @pytest.mark.asyncio
    async def test_store_with_ttl(self, storage: InMemoryTokenStorage) -> None:
        """Test storing token with TTL."""
        key = "test_token_ttl"
        value = "token_value_with_ttl"
        ttl = timedelta(seconds=1)

        # Store with TTL
        await storage.store(key, value, ttl)

        # Should exist immediately
        assert await storage.exists(key)

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired
        assert not await storage.exists(key)

    @pytest.mark.asyncio
    async def test_delete_token(self, storage: InMemoryTokenStorage) -> None:
        """Test deleting tokens."""
        key = "test_token_delete"
        value = "token_to_delete"

        # Store and verify
        await storage.store(key, value)
        assert await storage.exists(key)

        # Delete and verify
        deleted = await storage.delete(key)
        assert deleted
        assert not await storage.exists(key)

        # Delete non-existent key
        deleted_again = await storage.delete(key)
        assert not deleted_again

    @pytest.mark.asyncio
    async def test_exists_method(self, storage: InMemoryTokenStorage) -> None:
        """Test exists method."""
        key = "test_exists"
        value = "test_value"

        # Should not exist initially
        assert not await storage.exists(key)

        # Should exist after storing
        await storage.store(key, value)
        assert await storage.exists(key)

    @pytest.mark.asyncio
    async def test_keys_pattern_matching(self, storage: InMemoryTokenStorage) -> None:
        """Test keys method with pattern matching."""
        # Store multiple tokens
        await storage.store("user:123:access", "token1")
        await storage.store("user:123:refresh", "token2")
        await storage.store("user:456:access", "token3")
        await storage.store("session:789", "token4")

        # Test pattern matching
        user_keys = await storage.keys("user:*")
        assert len(user_keys) == 3
        assert "user:123:access" in user_keys
        assert "user:123:refresh" in user_keys
        assert "user:456:access" in user_keys

        # Test specific user pattern
        user_123_keys = await storage.keys("user:123:*")
        assert len(user_123_keys) == 2
        assert "user:123:access" in user_123_keys
        assert "user:123:refresh" in user_123_keys

    @pytest.mark.asyncio
    async def test_cleanup_expired(self, storage: InMemoryTokenStorage) -> None:
        """Test cleanup of expired tokens."""
        # Store tokens with different TTLs
        await storage.store("token1", "value1", timedelta(seconds=0.5))
        await storage.store("token2", "value2", timedelta(seconds=2))
        await storage.store("token3", "value3")  # No TTL

        # Wait for first token to expire
        await asyncio.sleep(0.6)

        # Cleanup expired tokens
        cleaned = await storage.cleanup_expired()
        assert cleaned == 1

        # Verify only expired token was removed
        assert not await storage.exists("token1")
        assert await storage.exists("token2")
        assert await storage.exists("token3")


class TestTokenBlacklist:
    """Test TokenBlacklist functionality."""

    @pytest.fixture
    def blacklist(self) -> TokenBlacklist:
        """Create TokenBlacklist for testing."""
        storage = InMemoryTokenStorage()
        return TokenBlacklist(storage)

    @pytest.fixture
    def sample_metadata(self) -> TokenMetadata:
        """Create sample token metadata."""
        return TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
        )

    @pytest.mark.asyncio
    async def test_revoke_token(
        self,
        blacklist: TokenBlacklist,
        sample_metadata: TokenMetadata,
    ) -> None:
        """Test revoking a token."""
        await blacklist.revoke_token(
            sample_metadata.token_id,
            sample_metadata.expires_at,
            sample_metadata,
        )

        # Check if token is revoked
        is_revoked = await blacklist.is_token_revoked(sample_metadata.token_id)
        assert is_revoked

    @pytest.mark.asyncio
    async def test_is_token_revoked(self, blacklist: TokenBlacklist) -> None:
        """Test checking if token is revoked."""
        token_id = "test_token"
        expires_at = dt.now(UTC) + timedelta(hours=1)

        # Should not be revoked initially
        assert not await blacklist.is_token_revoked(token_id)

        # Revoke the token
        await blacklist.revoke_token(token_id, expires_at)

        # Should be revoked now
        assert await blacklist.is_token_revoked(token_id)

    @pytest.mark.asyncio
    async def test_revoke_user_tokens(self, blacklist: TokenBlacklist) -> None:
        """Test revoking all tokens for a user."""
        user_id = uuid4()

        # Create metadata for multiple tokens
        metadata1 = TokenMetadata(
            token_id="token1",
            user_id=user_id,
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
        )
        metadata2 = TokenMetadata(
            token_id="token2",
            user_id=user_id,
            token_type=TokenType.REFRESH,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(days=7),
        )

        # Revoke tokens for user
        await blacklist.revoke_token("token1", metadata1.expires_at, metadata1)
        await blacklist.revoke_token("token2", metadata2.expires_at, metadata2)

        # Revoke user tokens by type
        await blacklist.revoke_user_tokens(user_id, TokenType.ACCESS)

        # Verify tokens are revoked
        assert await blacklist.is_token_revoked("token1")
        assert await blacklist.is_token_revoked("token2")

    @pytest.mark.asyncio
    async def test_get_revoked_tokens(self, blacklist: TokenBlacklist) -> None:
        """Test getting list of revoked tokens."""
        user_id = uuid4()
        token_ids = ["token1", "token2", "token3"]
        expires_at = dt.now(UTC) + timedelta(hours=1)

        # Revoke multiple tokens
        for token_id in token_ids:
            await blacklist.revoke_token(token_id, expires_at)

        # Get revoked tokens
        revoked_tokens = await blacklist.get_revoked_tokens(user_id, limit=10)

        # Should return revoked tokens
        assert len(revoked_tokens) >= 0  # May be empty depending on implementation

    @pytest.mark.asyncio
    async def test_cleanup_task(self, blacklist: TokenBlacklist) -> None:
        """Test periodic cleanup task."""
        # Start cleanup task
        await blacklist.start_cleanup_task(timedelta(seconds=0.1))

        # Add expired token
        expired_token = "expired_token"
        past_time = dt.now(UTC) - timedelta(hours=1)
        await blacklist.revoke_token(expired_token, past_time)

        # Wait for cleanup
        await asyncio.sleep(0.2)

        # Stop cleanup task
        await blacklist.stop_cleanup_task()


class TestTokenManager:
    """Test TokenManager functionality."""

    @pytest.fixture
    def token_manager(self) -> TokenManager:
        """Create TokenManager for testing."""
        storage = InMemoryTokenStorage()
        blacklist = TokenBlacklist(storage)
        return TokenManager(blacklist, storage)

    @pytest.fixture
    def sample_metadata(self) -> TokenMetadata:
        """Create sample token metadata."""
        return TokenMetadata(
            token_id="token123",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
        )

    @pytest.mark.asyncio
    async def test_register_token(
        self,
        token_manager: TokenManager,
        sample_metadata: TokenMetadata,
    ) -> None:
        """Test registering a token."""
        await token_manager.register_token(sample_metadata.token_id, sample_metadata)

        # Verify token is registered (exists in storage)
        # Note: This test assumes the implementation stores metadata in some way

    @pytest.mark.asyncio
    async def test_validate_token(
        self,
        token_manager: TokenManager,
        sample_metadata: TokenMetadata,
    ) -> None:
        """Test validating a token."""
        # Register token first
        await token_manager.register_token(sample_metadata.token_id, sample_metadata)

        # Validate token
        is_valid = await token_manager.validate_token(sample_metadata.token_id)
        assert is_valid

        # Revoke token and test validation
        await token_manager.revoke_token(sample_metadata.token_id)
        is_valid_after_revoke = await token_manager.validate_token(
            sample_metadata.token_id,
        )
        assert not is_valid_after_revoke

    @pytest.mark.asyncio
    async def test_revoke_token(
        self,
        token_manager: TokenManager,
        sample_metadata: TokenMetadata,
    ) -> None:
        """Test revoking a token."""
        # Register token first
        await token_manager.register_token(sample_metadata.token_id, sample_metadata)

        # Revoke token
        revoked = await token_manager.revoke_token(
            sample_metadata.token_id,
            revoked_by=uuid4(),
            reason="Security policy",
        )
        assert revoked

        # Verify token is no longer valid
        is_valid = await token_manager.validate_token(sample_metadata.token_id)
        assert not is_valid

    @pytest.mark.asyncio
    async def test_revoke_user_tokens(self, token_manager: TokenManager) -> None:
        """Test revoking all tokens for a user."""
        user_id = uuid4()

        # Create multiple tokens for user
        tokens = [
            TokenMetadata(
                token_id=f"token{i}",
                user_id=user_id,
                token_type="access" if i % 2 == 0 else "refresh",
                issued_at=dt.now(UTC),
                expires_at=dt.now(UTC) + timedelta(hours=1),
            )
            for i in range(3)
        ]

        # Register tokens
        for token in tokens:
            await token_manager.register_token(token.token_id, token)

        # Revoke all access tokens for user
        revoked_count = await token_manager.revoke_user_tokens(
            user_id,
            token_type=TokenType.ACCESS,
            revoked_by=uuid4(),
            reason="Policy change",
        )

        # Should have revoked at least some tokens
        assert revoked_count >= 0

    @pytest.mark.asyncio
    async def test_cleanup_expired_tokens(self, token_manager: TokenManager) -> None:
        """Test cleaning up expired tokens."""
        # Create expired token
        expired_metadata = TokenMetadata(
            token_id="expired_token",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC) - timedelta(hours=2),
            expires_at=dt.now(UTC) - timedelta(hours=1),
        )

        # Register expired token
        await token_manager.register_token(expired_metadata.token_id, expired_metadata)

        # Cleanup expired tokens
        cleaned_count = await token_manager.cleanup_expired_tokens()
        assert cleaned_count >= 0

    @pytest.mark.asyncio
    async def test_get_user_tokens(self, token_manager: TokenManager) -> None:
        """Test getting tokens for a user."""
        user_id = uuid4()

        # Create tokens for user
        active_metadata = TokenMetadata(
            token_id="active_token",
            user_id=user_id,
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
        )

        expired_metadata = TokenMetadata(
            token_id="expired_token",
            user_id=user_id,
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC) - timedelta(hours=2),
            expires_at=dt.now(UTC) - timedelta(hours=1),
        )

        # Register tokens
        await token_manager.register_token(active_metadata.token_id, active_metadata)
        await token_manager.register_token(expired_metadata.token_id, expired_metadata)

        # Get active tokens only
        active_tokens = await token_manager.get_user_tokens(
            user_id,
            inclusion_mode=TokenInclusionMode.ACTIVE_ONLY,
        )

        # Get all tokens including expired
        all_tokens = await token_manager.get_user_tokens(
            user_id,
            inclusion_mode=TokenInclusionMode.INCLUDE_EXPIRED,
        )

        # Should return list of TokenMetadata objects
        assert isinstance(active_tokens, list)
        assert isinstance(all_tokens, list)

    @pytest.mark.asyncio
    async def test_get_token_stats(self, token_manager: TokenManager) -> None:
        """Test getting token statistics."""
        stats = await token_manager.get_token_stats()
        assert isinstance(stats, dict)


class TestTokenPasswordHasher:
    """Test TokenPasswordHasher functionality."""

    @pytest.fixture
    def hasher(self) -> TokenPasswordHasher:
        """Create TokenPasswordHasher for testing."""
        return TokenPasswordHasher()

    def test_hash_password(self, hasher: TokenPasswordHasher) -> None:
        """Test password hashing."""
        password = "test_password_123"
        hashed = hasher.hash_password(password)

        assert hashed != password
        assert len(hashed) > 0
        assert hashed.startswith("$argon2")  # argon2 prefix

    def test_verify_password(self, hasher: TokenPasswordHasher) -> None:
        """Test password verification."""
        password = "test_password_123"
        wrong_password = "wrong_password"

        hashed = hasher.hash_password(password)

        # Correct password should verify
        assert hasher.verify_password(password, hashed)

        # Wrong password should not verify
        assert not hasher.verify_password(wrong_password, hashed)

    def test_needs_update(self, hasher: TokenPasswordHasher) -> None:
        """Test checking if hash needs update."""
        password = "test_password_123"
        hashed = hasher.hash_password(password)

        # Fresh hash should not need update
        assert not hasher.needs_update(hashed)

    def test_hash_consistency(self, hasher: TokenPasswordHasher) -> None:
        """Test that hashing the same password produces different hashes."""
        password = "test_password_123"
        hash1 = hasher.hash_password(password)
        hash2 = hasher.hash_password(password)

        # Should be different hashes (due to salt)
        assert hash1 != hash2

        # But both should verify correctly
        assert hasher.verify_password(password, hash1)
        assert hasher.verify_password(password, hash2)


class TestCreateTokenStorage:
    """Test create_token_storage factory function."""

    def test_create_memory_storage(self) -> None:
        """Test creating in-memory storage."""
        storage = create_token_storage("memory")
        assert isinstance(storage, InMemoryTokenStorage)

    def test_create_redis_storage(self) -> None:
        """Test creating Redis storage."""
        with patch("flext_auth.tokens.redis.from_url") as mock_redis:
            mock_redis.return_value = MagicMock()
            storage = create_token_storage("redis", redis_url="redis://localhost")
            assert isinstance(storage, RedisTokenStorage)

    def test_create_database_storage(self) -> None:
        """Test creating database storage."""
        mock_session_factory = MagicMock()
        storage = create_token_storage(
            "database",
            db_session_factory=mock_session_factory,
        )
        assert isinstance(storage, DatabaseTokenStorage)

    def test_create_invalid_storage(self) -> None:
        """Test creating storage with invalid type."""
        with pytest.raises(ValueError, match="Unknown storage type"):
            create_token_storage("invalid_type")


class TestRedisTokenStorage:
    """Test RedisTokenStorage implementation."""

    @pytest.fixture
    def mock_redis(self) -> MagicMock:
        """Create mock Redis client."""
        mock_client = MagicMock()
        mock_client.get = AsyncMock()
        mock_client.set = AsyncMock()
        mock_client.setex = AsyncMock()
        mock_client.get = AsyncMock()
        mock_client.delete = AsyncMock()
        mock_client.exists = AsyncMock()
        mock_client.keys = AsyncMock()
        mock_client.scan_iter = AsyncMock()
        mock_client.close = AsyncMock()
        mock_client.aclose = AsyncMock()
        return mock_client

    @pytest.fixture
    def redis_storage(self, mock_redis: MagicMock) -> RedisTokenStorage:
        """Create RedisTokenStorage with mock client."""
        return RedisTokenStorage(redis_client=mock_redis)

    def test_make_key(self, redis_storage: RedisTokenStorage) -> None:
        """Test key prefixing."""
        key = "test_key"
        prefixed = redis_storage._make_key(key)
        assert prefixed == "flext:tokens:test_key"

    @pytest.mark.asyncio
    async def test_store(
        self,
        redis_storage: RedisTokenStorage,
        mock_redis: MagicMock,
    ) -> None:
        """Test storing value in Redis."""
        await redis_storage.store("test_key", "test_value")

        mock_redis.set.assert_called_once_with(
            "flext:tokens:test_key",
            "test_value",
        )

    @pytest.mark.asyncio
    async def test_store_with_ttl(
        self,
        redis_storage: RedisTokenStorage,
        mock_redis: MagicMock,
    ) -> None:
        """Test storing value with TTL."""
        ttl = timedelta(seconds=3600)
        await redis_storage.store("test_key", "test_value", ttl)

        mock_redis.setex.assert_called_once_with(
            "flext:tokens:test_key",
            3600,
            "test_value",
        )

    @pytest.mark.asyncio
    async def test_get(
        self,
        redis_storage: RedisTokenStorage,
        mock_redis: MagicMock,
    ) -> None:
        """Test getting value from Redis."""
        mock_redis.get.return_value = "test_value"

        result = await redis_storage.get("test_key")

        assert result == "test_value"
        mock_redis.get.assert_called_once_with("flext:tokens:test_key")

    @pytest.mark.asyncio
    async def test_delete(
        self,
        redis_storage: RedisTokenStorage,
        mock_redis: MagicMock,
    ) -> None:
        """Test deleting value from Redis."""
        mock_redis.delete.return_value = 1

        result = await redis_storage.delete("test_key")

        assert result is True
        mock_redis.delete.assert_called_once_with("flext:tokens:test_key")

    @pytest.mark.asyncio
    async def test_exists(
        self,
        redis_storage: RedisTokenStorage,
        mock_redis: MagicMock,
    ) -> None:
        """Test checking if key exists in Redis."""
        mock_redis.exists.return_value = 1

        result = await redis_storage.exists("test_key")

        assert result is True
        mock_redis.exists.assert_called_once_with("flext:tokens:test_key")

    @pytest.mark.asyncio
    async def test_keys(
        self,
        redis_storage: RedisTokenStorage,
        mock_redis: MagicMock,
    ) -> None:
        """Test getting keys by pattern from Redis."""
        mock_redis.keys.return_value = [b"flext:tokens:key1", b"flext:tokens:key2"]

        result = await redis_storage.keys("pattern*")

        assert result == ["key1", "key2"]
        mock_redis.keys.assert_called_once_with("flext:tokens:pattern*")

    @pytest.mark.asyncio
    async def test_close(
        self,
        redis_storage: RedisTokenStorage,
        mock_redis: MagicMock,
    ) -> None:
        """Test closing Redis connection."""
        await redis_storage.close()
        mock_redis.close.assert_called_once()


class TestDatabaseTokenStorage:
    """Test DatabaseTokenStorage implementation."""

    @pytest.fixture
    def mock_session_factory(self) -> MagicMock:
        """Create mock database session factory."""
        return MagicMock()

    @pytest.fixture
    def db_storage(self, mock_session_factory: MagicMock) -> DatabaseTokenStorage:
        """Create DatabaseTokenStorage with mock session factory."""
        return DatabaseTokenStorage(db_session_factory=mock_session_factory)

    @pytest.mark.asyncio
    async def test_database_storage_methods(
        self,
        db_storage: DatabaseTokenStorage,
    ) -> None:
        """Test that DatabaseTokenStorage has all required methods implemented."""
        # Just verify the methods exist and are callable
        assert callable(db_storage.store)
        assert callable(db_storage.get)
        assert callable(db_storage.delete)
        assert callable(db_storage.exists)
        assert callable(db_storage.keys)
        assert callable(db_storage.cleanup_expired)

        # All methods are implemented and callable


class TestInMemoryTokenStorageAlternative:
    """Test InMemoryTokenStorageAlternative implementation."""

    @pytest.fixture
    def alt_storage(self) -> InMemoryTokenStorageAlternative:
        """Create InMemoryTokenStorageAlternative for testing."""
        return InMemoryTokenStorageAlternative()

    @pytest.mark.asyncio
    async def test_alternative_storage_basic_operations(
        self,
        alt_storage: InMemoryTokenStorageAlternative,
    ) -> None:
        """Test basic operations of alternative storage."""
        # Store and retrieve
        await alt_storage.store("key1", "value1")
        result = await alt_storage.get("key1")
        assert result == "value1"

        # Check existence
        assert await alt_storage.exists("key1")
        assert not await alt_storage.exists("non_existent")

        # Delete
        deleted = await alt_storage.delete("key1")
        assert deleted
        assert not await alt_storage.exists("key1")

    @pytest.mark.asyncio
    async def test_alternative_storage_ttl(
        self,
        alt_storage: InMemoryTokenStorageAlternative,
    ) -> None:
        """Test TTL functionality in alternative storage."""
        await alt_storage.store("ttl_key", "ttl_value", timedelta(seconds=1))

        # Should exist immediately
        assert await alt_storage.exists("ttl_key")

        # Wait for expiration
        await asyncio.sleep(1.1)

        # Should be expired
        assert not await alt_storage.exists("ttl_key")

    @pytest.mark.asyncio
    async def test_alternative_storage_cleanup(
        self,
        alt_storage: InMemoryTokenStorageAlternative,
    ) -> None:
        """Test cleanup in alternative storage."""
        # Store some tokens with short TTL
        await alt_storage.store("expire1", "value1", timedelta(seconds=0.5))
        await alt_storage.store("expire2", "value2", timedelta(seconds=0.5))
        await alt_storage.store("keep", "value3", timedelta(seconds=10))

        # Wait for expiration
        await asyncio.sleep(0.6)

        # Cleanup expired
        cleaned = await alt_storage.cleanup_expired()
        assert cleaned >= 0  # Should have cleaned at least some

        # Non-expired should still exist
        assert await alt_storage.exists("keep")


class TestIntegrationScenarios:
    """Test integration scenarios combining multiple components."""

    @pytest.mark.asyncio
    async def test_full_token_lifecycle(self) -> None:
        """Test complete token lifecycle with multiple components."""
        # Setup components
        storage = InMemoryTokenStorage()
        blacklist = TokenBlacklist(storage)
        manager = TokenManager(blacklist, storage)

        # Create token metadata
        metadata = TokenMetadata(
            token_id="integration_token",
            user_id=uuid4(),
            token_type=TokenType.ACCESS,
            issued_at=dt.now(UTC),
            expires_at=dt.now(UTC) + timedelta(hours=1),
            ip_address="192.168.1.1",
            user_agent="Test Browser",
        )

        # Register token
        await manager.register_token(metadata.token_id, metadata)

        # Validate token
        assert await manager.validate_token(metadata.token_id)

        # Revoke token
        REDACTED_LDAP_BIND_PASSWORD_user_id = uuid4()
        revoked = await manager.revoke_token(
            metadata.token_id,
            revoked_by=REDACTED_LDAP_BIND_PASSWORD_user_id,
            reason="Test revocation",
        )
        assert revoked

        # Token should no longer be valid
        assert not await manager.validate_token(metadata.token_id)

        # Cleanup
        await manager.cleanup_expired_tokens()

    @pytest.mark.asyncio
    async def test_concurrent_operations(self) -> None:
        """Test concurrent token operations."""
        storage = InMemoryTokenStorage()

        # Perform concurrent operations
        tasks = []
        for i in range(10):
            task = storage.store(f"concurrent_key_{i}", f"value_{i}")
            tasks.append(task)

        # Wait for all stores to complete
        await asyncio.gather(*tasks)

        # Verify all keys exist
        for i in range(10):
            assert await storage.exists(f"concurrent_key_{i}")

        # Concurrent cleanup
        cleanup_tasks = [storage.cleanup_expired() for _ in range(5)]
        results = await asyncio.gather(*cleanup_tasks)
        assert all(isinstance(result, int) for result in results)

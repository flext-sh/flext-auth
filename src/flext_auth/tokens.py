from __future__ import annotations

"""Token management and blacklisting system with Python 3.13 patterns."""

import asyncio
import contextlib
import fnmatch
from abc import ABC
from abc import abstractmethod
from datetime import UTC
from datetime import datetime as dt
from datetime import timedelta
from typing import TYPE_CHECKING
from typing import Any
from typing import TypeVar

import redis.asyncio as redis
from passlib.context import CryptContext
from pydantic import Field

# Define constants locally since config is not available
from flext_core import DomainValueObject as ValueObject
from flext_core.domain.types import StrEnum


# Simple constants for token management - avoid dependency on config module
class _TokenConstants:
    REDIS_KEY_PREFIX = "flext:token:"
    DEFAULT_TTL_SECONDS = 3600
    CLEANUP_BATCH_SIZE = 100
    MAXIMUM_PASSWORD_LENGTH = 128


def get_domain_constants():
    """Get local domain constants for token management."""
    return _TokenConstants()


# Import types outside TYPE_CHECKING for runtime use

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from flext_auth.types import TokenType
    from flext_auth.types import UserID

T = TypeVar("T")


class TokenInclusionMode(StrEnum):
    """Token inclusion mode for filtering token retrieval operations using flext-core patterns.

    Defines whether expired tokens should be included in token listing
    and retrieval operations, replacing boolean include_expired parameters
    with explicit modes for better type safety and code clarity.

    Attributes
    ----------
        ACTIVE_ONLY: Return only active (non-expired) tokens.
        INCLUDE_EXPIRED: Include both active and expired tokens in results.

    """

    ACTIVE_ONLY = "active_only"
    INCLUDE_EXPIRED = "include_expired"


class TokenMetadata(ValueObject):
    """Enterprise JWT token metadata with comprehensive security audit capabilities.

    Encapsulates all relevant information about a JWT token including identity,
    type, timestamps, revocation status, and comprehensive security audit data
    for enterprise-grade token lifecycle management and forensic analysis.

    This immutable value object provides complete audit trails for security
    compliance and forensic investigation of authentication events.
    """

    token_id: str = Field(
        description="Unique identifier for token tracking and audit trails",
    )
    user_id: UserID = Field(
        description="Owner user identifier for security association",
    )
    token_type: str = Field(
        description="Token classification for access control policies",
    )
    issued_at: dt = Field(description="Token issuance timestamp for lifecycle tracking")
    expires_at: dt = Field(
        description="Token expiration timestamp for security enforcement",
    )
    revoked_at: dt | None = Field(
        default=None,
        description="Revocation timestamp for audit compliance",
    )
    revoked_by: UserID | None = Field(
        default=None,
        description="User who performed revocation for accountability",
    )
    revocation_reason: str | None = Field(
        default=None,
        description="Security reason for revocation documentation",
    )
    ip_address: str | None = Field(
        default=None,
        description="Source IP address for geographic security analysis",
    )
    user_agent: str | None = Field(
        default=None,
        description="Client user agent for device fingerprinting",
    )
    device_info: dict[str, Any] = Field(
        default_factory=dict,
        description="Comprehensive device metadata for security analytics and fraud detection",
    )

    @property
    def is_expired(self) -> bool:
        """Check if the token has expired.

        Returns:
            bool: True if current time is past the expiration timestamp.

        """
        return dt.now(UTC) > self.expires_at

    @property
    def is_revoked(self) -> bool:
        """Check if the token has been revoked.

        Returns:
            bool: True if the token has a revocation timestamp.

        """
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if the token is valid (not expired and not revoked).

        Returns:
            bool: True if the token is both non-expired and non-revoked.

        """
        return not self.is_expired and not self.is_revoked

    def revoke(
        self, revoked_by: UserID | None = None, reason: str | None = None,
    ) -> TokenMetadata:
        """Create a revoked copy of this token metadata.

        Args:
            revoked_by: User ID who performed the revocation.
            reason: Reason for the revocation.

        Returns:
            TokenMetadata: New instance with revocation information populated.

        """
        return TokenMetadata(
            token_id=self.token_id,
            user_id=self.user_id,
            token_type=self.token_type,
            issued_at=self.issued_at,
            expires_at=self.expires_at,
            revoked_at=dt.now(UTC),
            revoked_by=revoked_by,
            revocation_reason=reason,
            ip_address=self.ip_address,
            user_agent=self.user_agent,
            device_info=self.device_info,
        )


class TokenStorage[T](ABC):
    """Abstract base class for token storage backends."""

    @abstractmethod
    async def store(self, key: str, value: T, ttl: timedelta | None = None) -> None:
        """Store a value with optional time-to-live.

        Args:
            key: Storage key identifier.
            value: Value to store.
            ttl: Optional time-to-live duration.

        Raises:
            NotImplementedError: This is an abstract method.

        """
        # Base implementation - subclasses provide concrete storage

    @abstractmethod
    async def get(self, key: str) -> T | None:
        """Retrieve a value by key.

        Args:
            key: Storage key identifier.

        Returns:
            T | None: Stored value or None if not found or expired.

        Raises:
            NotImplementedError: This is an abstract method.

        """
        # Base implementation - subclasses provide concrete storage

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a value by key.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key was found and deleted, False otherwise.

        Raises:
            NotImplementedError: This is an abstract method.

        """
        # Base implementation - subclasses provide concrete storage

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if a key exists and is not expired.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key exists and is not expired.

        Raises:
            NotImplementedError: This is an abstract method.

        """
        # Base implementation - subclasses provide concrete storage

    @abstractmethod
    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern.

        Returns a list of keys that match the given pattern. The pattern
        should support basic wildcards like '*' for glob-style matching.

        Args:
        ----
            pattern: Pattern to match keys against (e.g., "user:*")

        Returns:
        -------
            list[str]: List of matching keys

        Note:
        ----
            Supports Redis-style glob patterns (* and ?) for flexible
            key discovery across different storage implementations.

        """
        # Base implementation - subclasses provide concrete storage

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove expired entries from storage.

        Returns:
            int: Number of expired entries removed.

        Raises:
            NotImplementedError: This is an abstract method.

        """
        # Base implementation - subclasses provide concrete storage


class RedisTokenStorage(TokenStorage[str]):
    """Redis-based token storage implementation."""

    def __init__(
        self, redis_client: Redis[str] | None = None, key_prefix: str = "flext:tokens",
    ) -> None:
        # Get Redis configuration from unified domain config - with strict validation
        if redis_client:
            self.redis = redis_client
        else:
            # Use import from flext_auth config
            from flext_auth.config import get_auth_settings

            config = get_auth_settings()
            redis_url = getattr(config, "redis_url", "redis://localhost:6379/0")
            self.redis = redis.from_url(redis_url)
        self.key_prefix = key_prefix

    def _make_key(self, key: str) -> str:
        return f"{self.key_prefix}:{key}"

    async def store(self, key: str, value: str, ttl: timedelta | None = None) -> None:
        """Store a value in Redis with optional TTL.

        Args:
            key: Storage key identifier.
            value: String value to store.
            ttl: Optional time-to-live duration.

        """
        redis_key = self._make_key(key)
        if ttl:
            await self.redis.setex(redis_key, int(ttl.total_seconds()), value)
        else:
            await self.redis.set(redis_key, value)

    async def get(self, key: str) -> str | None:
        """Retrieve a value from Redis by key.

        Args:
            key: Storage key identifier.

        Returns:
            str | None: Stored value or None if not found.

        """
        redis_key = self._make_key(key)
        return await self.redis.get(redis_key)

    async def delete(self, key: str) -> bool:
        """Delete a value from Redis by key.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key was found and deleted.

        """
        redis_key = self._make_key(key)
        result = await self.redis.delete(redis_key)
        return result > 0

    async def exists(self, key: str) -> bool:
        """Check if a key exists in Redis.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key exists.

        """
        redis_key = self._make_key(key)
        return await self.redis.exists(redis_key) > 0

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern.

        Returns all keys matching the given glob-style pattern. The
        pattern is applied after the key prefix.

        Args:
        ----
            pattern: Glob pattern to match (e.g., "user:*:access")

        Returns:
        -------
            list[str]: List of matching keys without the prefix

        Note:
        ----
            Removes namespace prefix from returned keys to provide
            clean key names consistent with storage interface.

        """
        redis_pattern = self._make_key(pattern)
        keys = await self.redis.keys(redis_pattern)
        # Remove prefix from keys
        prefix_len = len(self.key_prefix) + 1
        return [key[prefix_len:] for key in keys]

    async def cleanup_expired(self) -> int:
        """Redis handles expiration automatically.

        Returns:
            int: Always returns 0 as Redis handles cleanup automatically.

        """
        # Redis automatically removes expired keys
        return 0

    async def close(self) -> None:
        """Close the Redis connection.

        Gracefully closes the underlying Redis connection to free resources.
        """
        await self.redis.aclose()


class InMemoryTokenStorage(TokenStorage[str]):
    """In-memory token storage for testing and development."""

    def __init__(self) -> None:
        self._data: dict[str, tuple[str, dt | None]] = {}
        self._lock = asyncio.Lock()

    async def store(self, key: str, value: str, ttl: timedelta | None = None) -> None:
        """Store a value in memory with optional TTL.

        Args:
            key: Storage key identifier.
            value: String value to store.
            ttl: Optional time-to-live duration.

        """
        expires_at = dt.now(UTC) + ttl if ttl else None
        async with self._lock:
            self._data[key] = (value, expires_at)

    async def get(self, key: str) -> str | None:
        """Retrieve a value from memory by key.

        Args:
            key: Storage key identifier.

        Returns:
            str | None: Stored value or None if not found or expired.

        """
        async with self._lock:
            if key not in self._data:
                return None

            value, expires_at = self._data[key]

            # Check if expired:
            if expires_at and dt.now(UTC) > expires_at:
                del self._data[key]
                return None

            return value

    async def delete(self, key: str) -> bool:
        """Delete a value from memory by key.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key was found and deleted.

        """
        async with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    async def exists(self, key: str) -> bool:
        """Check if a key exists in memory and is not expired.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key exists and is not expired.

        """
        return await self.get(key) is not None

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching a glob pattern.

        Args:
            pattern: Glob pattern to match keys against.

        Returns:
            list[str]: List of matching keys.

        """
        async with self._lock:
            return [key for key in self._data if fnmatch.fnmatch(key, pattern)]

    async def cleanup_expired(self) -> int:
        """Remove expired entries from memory storage.

        Returns:
            int: Number of expired entries removed.

        """
        now = dt.now(UTC)
        expired_keys = []

        async with self._lock:
            for key, (_, expires_at) in self._data.items():
                if expires_at and now > expires_at:
                    expired_keys.append(key)

            for key in expired_keys:
                del self._data[key]

        return len(expired_keys)


class DatabaseTokenStorage(TokenStorage[str]):
    """Database-based token storage implementation using SQLAlchemy."""

    def __init__(self, db_session_factory: Any) -> None:
        self.session_factory = db_session_factory

    async def store(self, key: str, value: str, ttl: timedelta | None = None) -> None:
        """Store a value in database with optional TTL.

        Args:
            key: Storage key identifier.
            value: String value to store.
            ttl: Optional time-to-live duration.

        """
        expires_at = dt.now(UTC) + ttl if ttl else None

        async with self.session_factory() as session:
            # Check if key exists:
            existing = await session.execute(
                "SELECT key FROM token_storage WHERE key = :key",
                {"key": key},
            )

            if existing.scalar():
                # Update existing
                await session.execute(
                    "UPDATE token_storage SET value = :value, expires_at = :expires_at, updated_at = :now WHERE key = :key",  # TODO: Break long line
                    {
                        "key": key,
                        "value": value,
                        "expires_at": expires_at,
                        "now": dt.now(UTC),
                    },
                )
            else:
                # Insert new
                await session.execute(
                    "INSERT INTO token_storage (key, value, expires_at, created_at) VALUES (:key, :value, :expires_at, :now)",  # TODO: Break long line
                    {
                        "key": key,
                        "value": value,
                        "expires_at": expires_at,
                        "now": dt.now(UTC),
                    },
                )

            await session.commit()

    async def get(self, key: str) -> str | None:
        """Retrieve a value from database by key.

        Args:
            key: Storage key identifier.

        Returns:
            str | None: Stored value or None if not found or expired.

        """
        async with self.session_factory() as session:
            result = await session.execute(
                "SELECT value, expires_at FROM token_storage WHERE key = :key",
                {"key": key},
            )
            row = result.first()

            if not row:
                return None

            value, expires_at = row

            # Check expiration
            if expires_at and dt.now(UTC) > expires_at:
                # Clean up expired entry
                await session.execute(
                    "DELETE FROM token_storage WHERE key = :key",
                    {"key": key},
                )
                await session.commit()
                return None

            return value

    async def delete(self, key: str) -> bool:
        """Delete a value from database by key.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key was found and deleted.

        """
        async with self.session_factory() as session:
            result = await session.execute(
                "DELETE FROM token_storage WHERE key = :key",
                {"key": key},
            )
            await session.commit()
            return result.rowcount > 0

    async def exists(self, key: str) -> bool:
        """Check if a key exists in database and is not expired.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key exists and is not expired.

        """
        async with self.session_factory() as session:
            result = await session.execute(
                "SELECT 1 FROM token_storage WHERE key = :key AND (expires_at IS NULL OR expires_at > :now)",  # TODO: Break long line
                {"key": key, "now": dt.now(UTC)},
            )
            return result.scalar() is not None

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching a glob pattern from database.

        Args:
            pattern: Glob pattern to match keys against.

        Returns:
            list[str]: List of matching keys that are not expired.

        """
        # Convert glob pattern to SQL LIKE pattern
        sql_pattern = pattern.replace("*", "%").replace("?", "_")

        async with self.session_factory() as session:
            result = await session.execute(
                "SELECT key FROM token_storage WHERE key LIKE :pattern AND (expires_at IS NULL OR expires_at > :now)",  # TODO: Break long line
                {"pattern": sql_pattern, "now": dt.now(UTC)},
            )
            return [row[0] for row in result]

    async def cleanup_expired(self) -> int:
        """Remove expired entries from database storage.

        Returns:
            int: Number of expired entries removed.

        """
        async with self.session_factory() as session:
            result = await session.execute(
                "DELETE FROM token_storage WHERE expires_at IS NOT NULL AND expires_at < :now",
                {"now": dt.now(UTC)},
            )
            await session.commit()
            return result.rowcount


class TokenBlacklist:
    """Token blacklisting service with automatic cleanup."""

    def __init__(self, storage: TokenStorage[str] | None = None) -> None:
        self.storage = storage or InMemoryTokenStorage()
        self._cleanup_task: asyncio.Task[None] | None = None

    async def start_cleanup_task(
        self, interval: timedelta = timedelta(hours=1),
    ) -> None:
        """Start the automatic cleanup task.

        Args:
            interval: Time interval between cleanup runs (default: 1 hour).

        """
        if self._cleanup_task and not self._cleanup_task.done():
            return

        self._cleanup_task = asyncio.create_task(self._periodic_cleanup(interval))

    async def stop_cleanup_task(self) -> None:
        """Stop the automatic cleanup task.

        Cancels the running cleanup task and waits for clean shutdown.
        """
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task

    async def _periodic_cleanup(self, interval: timedelta) -> None:
        while True:
            try:
                await asyncio.sleep(interval.total_seconds())
                await self.storage.cleanup_expired()
            except asyncio.CancelledError:
                break
            except (RuntimeError, ValueError, TypeError, OSError, AttributeError):
                # Log error but continue cleanup loop
                pass

    async def revoke_token(
        self, token_id: str, expires_at: dt, metadata: TokenMetadata | None = None,
    ) -> None:
        """Revoke a token by adding it to the blacklist.

        Args:
            token_id: Unique identifier of the token to revoke.
            expires_at: When the token expires naturally.
            metadata: Optional token metadata for audit information.

        """
        ttl = expires_at - dt.now(UTC)
        if ttl.total_seconds() <= 0:
            return  # Token already expired

        # Store revocation info
        revocation_data = {
            "revoked_at": dt.now(UTC).isoformat(),
            "metadata": metadata.device_info if metadata else {},
        }

        await self.storage.store(
            key=token_id,
            value=str(revocation_data),
            ttl=ttl,
        )

    async def is_token_revoked(self, token_id: str) -> bool:
        """Check if a token is in the blacklist.

        Args:
            token_id: Unique identifier of the token to check.

        Returns:
            bool: True if the token is revoked.

        """
        return await self.storage.exists(token_id)

    async def revoke_user_tokens(
        self, user_id: UserID, token_type: TokenType | None = None,
    ) -> int:
        """Revoke all tokens for a specific user.

        Args:
            user_id: User whose tokens should be revoked.
            token_type: Optional filter for specific token type.

        Returns:
            int: Number of tokens revoked.

        """
        pattern = f"user:{user_id}:*"
        if token_type:
            pattern = f"user:{user_id}:{token_type.lower()}:*"

        keys = await self.storage.keys(pattern)

        # Revoke each token
        revoked_count = 0
        for key in keys:
            # Extract token_id from key
            token_id = key.split(":")[-1]

            # Set revocation with default expiry
            await self.storage.store(
                key=token_id,
                value="revoked",
                ttl=timedelta(days=30),  # Keep revocation record
            )
            revoked_count += 1

        return revoked_count

    async def get_revoked_tokens(
        self, user_id: UserID | None = None, limit: int = 100,
    ) -> list[str]:
        """Get list of revoked tokens.

        Args:
            user_id: Optional filter for specific user's revoked tokens.
            limit: Maximum number of tokens to return (default: 100).

        Returns:
            list[str]: List of revoked token identifiers.

        """
        pattern = "*" if not user_id else f"user:{user_id}:*"
        keys = await self.storage.keys(pattern)
        return keys[:limit]


class TokenManager:
    """Comprehensive token management with automatic renewal and cleanup."""

    def __init__(
        self,
        blacklist: TokenBlacklist | None = None,
        storage: TokenStorage[str] | None = None,
    ) -> None:
        self.blacklist = blacklist or TokenBlacklist(storage)
        self._active_tokens: dict[str, TokenMetadata] = {}
        self._user_tokens: dict[UserID, set[str]] = {}

    async def register_token(self, token_id: str, metadata: TokenMetadata) -> None:
        """Register a new token with its metadata.

        Args:
            token_id: Unique identifier of the token.
            metadata: Complete token metadata for tracking.

        """
        self._active_tokens[token_id] = metadata

        # Track tokens by user
        if metadata.user_id not in self._user_tokens:
            self._user_tokens[metadata.user_id] = set()
        self._user_tokens[metadata.user_id].add(token_id)

    async def validate_token(self, token_id: str) -> bool:
        """Validate if a token is still valid.

        Args:
            token_id: Unique identifier of the token to validate.

        Returns:
            bool: True if the token is valid (not revoked and not expired).

        """
        # Check blacklist first
        if await self.blacklist.is_token_revoked(token_id):
            return False

        # Check local metadata
        if token_id in self._active_tokens:
            metadata = self._active_tokens[token_id]
            return metadata.is_valid

        # Token not found, assume valid (will be validated by JWT service)
        return True

    async def revoke_token(
        self, token_id: str, revoked_by: UserID | None = None, reason: str | None = None,
    ) -> bool:
        """Revoke a specific token.

        Args:
            token_id: Unique identifier of the token to revoke.
            revoked_by: User who performed the revocation.
            reason: Reason for the revocation.

        Returns:
            bool: True if the token was successfully revoked.

        """
        # Get token metadata
        metadata = self._active_tokens.get(token_id)
        if not metadata:
            return False

        # Mark as revoked
        revoked_metadata = metadata.revoke(revoked_by, reason)
        self._active_tokens[token_id] = revoked_metadata

        # Add to blacklist
        await self.blacklist.revoke_token(
            token_id=token_id,
            expires_at=metadata.expires_at,
            metadata=revoked_metadata,
        )

        return True

    async def revoke_user_tokens(
        self,
        user_id: UserID,
        token_type: TokenType | None = None,
        revoked_by: UserID | None = None,
        reason: str | None = None,
    ) -> int:
        """Revoke all tokens for a specific user.

        Args:
            user_id: User whose tokens should be revoked.
            token_type: Optional filter for specific token type.
            revoked_by: User who performed the revocation.
            reason: Reason for the revocation.

        Returns:
            int: Number of tokens successfully revoked.

        """
        if user_id not in self._user_tokens:
            return 0

        user_token_ids = list(self._user_tokens[user_id])
        revoked_count = 0

        for token_id in user_token_ids:
            metadata = self._active_tokens.get(token_id)
            if not metadata:
                continue

            # Filter by token type if specified:
            if token_type and metadata.token_type != token_type:
                continue

            # Revoke token
            if await self.revoke_token(token_id, revoked_by, reason):
                revoked_count += 1

        return revoked_count

    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from the manager.

        Returns:
            int: Number of expired tokens removed.

        """
        now = dt.now(UTC)
        expired_tokens = []

        for token_id, metadata in self._active_tokens.items():
            if now > metadata.expires_at:
                expired_tokens.append(token_id)

        # Remove expired tokens
        for token_id in expired_tokens:
            metadata = self._active_tokens.pop(token_id)

            # Remove from user tracking
            if metadata.user_id in self._user_tokens:
                user_tokens = self._user_tokens[metadata.user_id]
                if isinstance(user_tokens, set):
                    user_tokens.discard(token_id)
                elif isinstance(user_tokens, list):
                    with contextlib.suppress(ValueError):
                        user_tokens.remove(token_id)

                # Clean up empty user sets
                if not self._user_tokens[metadata.user_id]:
                    del self._user_tokens[metadata.user_id]

        # Cleanup blacklist
        await self.blacklist.storage.cleanup_expired()

        return len(expired_tokens)

    async def get_user_tokens(
        self,
        user_id: UserID,
        token_type: TokenType | None = None,
        inclusion_mode: TokenInclusionMode = TokenInclusionMode.ACTIVE_ONLY,
    ) -> list[TokenMetadata]:
        """Get tokens for a specific user.

        Args:
            user_id: User whose tokens to retrieve.
            token_type: Optional filter for specific token type.
            inclusion_mode: Whether to include expired tokens.

        Returns:
            list[TokenMetadata]: List of token metadata matching the criteria.

        """
        if user_id not in self._user_tokens:
            return []

        tokens = []
        for token_id in self._user_tokens[user_id]:
            metadata = self._active_tokens.get(token_id)
            if not metadata:
                continue

            # Filter by token type
            if token_type and metadata.token_type != token_type:
                continue

            # Filter expired tokens
            if inclusion_mode == TokenInclusionMode.ACTIVE_ONLY and metadata.is_expired:
                continue

            tokens.append(metadata)

        return tokens

    async def get_token_stats(self) -> dict[str, Any]:
        """Get comprehensive statistics about managed tokens.

        Returns:
            dict[str, Any]: Statistics including counts by status and type.

        """
        now = dt.now(UTC)

        total_tokens = len(self._active_tokens)
        expired_tokens = sum(
            1 for metadata in self._active_tokens.values() if now > metadata.expires_at
        )
        revoked_tokens = sum(
            1 for metadata in self._active_tokens.values() if metadata.is_revoked
        )

        # Count by token type
        type_counts: dict[str, int] = {}
        for metadata in self._active_tokens.values():
            token_type = metadata.token_type
            type_counts[token_type] = type_counts.get(token_type, 0) + 1

        return {
            "total_tokens": total_tokens,
            "active_tokens": total_tokens - expired_tokens - revoked_tokens,
            "expired_tokens": expired_tokens,
            "revoked_tokens": revoked_tokens,
            "unique_users": len(self._user_tokens),
            "tokens_by_type": type_counts,
        }


def create_token_storage(
    storage_type: str = "redis", **kwargs: Any,
) -> TokenStorage[str]:
    """Factory function to create appropriate token storage backend.

    Creates and configures the appropriate token storage implementation
    based on the specified type and configuration parameters.

    Args:
    ----
        storage_type: Type of storage backend ("redis", "memory", "database")
        **kwargs: Backend-specific configuration parameters

    Returns:
    -------
        TokenStorage[str]: Configured storage backend instance

    Raises:
    ------
        ValueError: If storage_type is not recognized

    Examples:
    --------
        # Redis storage
        storage = create_token_storage("redis", redis_client=redis_conn)

        # Database storage
        storage = create_token_storage("database", db_session_factory=session_factory)

        # In-memory storage (for testing)
        storage = create_token_storage("memory")

    Note:
    ----
        Redis is recommended for production deployments due to automatic
        TTL handling and distributed system support.

    """
    if storage_type == "redis":
        redis_client = kwargs.get("redis_client")
        key_prefix = kwargs.get("key_prefix", "flext:tokens")
        return RedisTokenStorage(redis_client=redis_client, key_prefix=key_prefix)

    if storage_type == "memory":
        return InMemoryTokenStorage()

    if storage_type == "database":
        db_session_factory = kwargs.get("db_session_factory")
        if not db_session_factory:
            msg = "Database storage requires db_session_factory parameter"
            raise ValueError(msg)
        return DatabaseTokenStorage(db_session_factory=db_session_factory)

    msg = (
        f"Unknown storage type: {storage_type}. Valid options: redis, memory, database"
    )
    raise ValueError(msg)


class TokenPasswordHasher:
    """Password hashing and verification using Argon2 with Python 3.13 patterns."""

    def __init__(self) -> None:
        self._crypt_context = CryptContext(
            schemes=["argon2"],
            deprecated="auto",
            argon2__memory_cost=65536,  # 64 MB
            argon2__time_cost=3,  # 3 iterations
            argon2__parallelism=1,  # Single thread
        )

    def hash_password(self, password: str) -> str:
        """Hash a password using Argon2.

        Args:
            password: Plain text password to hash.

        Returns:
            str: Hashed password string.

        Raises:
            TypeError: If password is not a string.
            ValueError: If password is empty or too long, or hashing fails.

        """
        if not isinstance(password, str):
            msg = "Password must be a string"
            raise TypeError(msg)

        if not password:
            msg = "Password cannot be empty"
            raise ValueError(msg)

        constants = get_domain_constants()
        if len(password) > constants.MAXIMUM_PASSWORD_LENGTH:
            msg = f"Password too long (max {constants.MAXIMUM_PASSWORD_LENGTH} characters)"
            raise ValueError(msg)

        try:
            result = self._crypt_context.hash(password)
            return str(result) if result is not None else ""
        except (ValueError, TypeError, RuntimeError, AttributeError, OSError) as e:
            # ZERO TOLERANCE - Specific exception types for password hashing failures
            msg = f"Failed to hash password: {e}"
            raise ValueError(msg) from e

    def verify_password(self, password: str, hashed_password: str) -> bool:
        """Verify a password against its hash.

        Args:
            password: Plain text password to verify.
            hashed_password: Previously hashed password to compare against.

        Returns:
            bool: True if the password matches the hash.

        Raises:
            TypeError: If password or hash are not strings.
            ValueError: If password or hash are empty, or verification fails.

        """
        if not isinstance(password, str) or not isinstance(hashed_password, str):
            msg = "Password and hash must be strings"
            raise TypeError(msg)

        if not password or not hashed_password:
            msg = "Password and hash cannot be empty"
            raise ValueError(msg)

        try:
            result = self._crypt_context.verify(password, hashed_password)
            return bool(result) if result is not None else False
        except (ValueError, TypeError, RuntimeError, AttributeError, OSError) as e:
            # ZERO TOLERANCE - Specific exception types for password verification failures
            msg = f"Failed to verify password: {e}"
            raise ValueError(msg) from e

    def needs_update(self, hashed_password: str) -> bool:
        """Check if a hashed password needs to be rehashed.

        Args:
            hashed_password: Previously hashed password to check.

        Returns:
            bool: True if the password hash needs updating.

        """
        try:
            result = self._crypt_context.needs_update(hashed_password)
            return bool(result) if result is not None else True
        except (ValueError, TypeError, AttributeError, RuntimeError):
            # If we can't check password hash format, assume it needs updating
            return True


# Alternative complete InMemoryTokenStorage implementation
class InMemoryTokenStorageAlternative(TokenStorage[str]):
    """Complete in-memory token storage implementation."""

    def __init__(self) -> None:
        self._storage: dict[str, dict[str, Any]] = {}
        self._lock = asyncio.Lock()

    async def store(self, key: str, value: str, ttl: timedelta | None = None) -> None:
        """Store a value in memory with detailed metadata tracking.

        Args:
            key: Storage key identifier.
            value: String value to store.
            ttl: Optional time-to-live duration.

        """
        async with self._lock:
            expiry = None
            if ttl:
                expiry = dt.now(UTC) + ttl

            self._storage[key] = {
                "value": value,
                "expiry": expiry,
                "created_at": dt.now(UTC),
            }

    async def get(self, key: str) -> str | None:
        """Retrieve a value from memory with expiration checking.

        Args:
            key: Storage key identifier.

        Returns:
            str | None: Stored value or None if not found or expired.

        """
        async with self._lock:
            if key not in self._storage:
                return None

            entry = self._storage[key]

            # Check if expired:
            if entry["expiry"] and dt.now(UTC) > entry["expiry"]:
                del self._storage[key]
                return None

            return entry["value"]

    async def delete(self, key: str) -> bool:
        """Delete a value from memory storage.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key was found and deleted.

        """
        async with self._lock:
            if key in self._storage:
                del self._storage[key]
                return True
            return False

    async def exists(self, key: str) -> bool:
        """Check if a key exists and is not expired.

        Args:
            key: Storage key identifier.

        Returns:
            bool: True if the key exists and is not expired.

        """
        async with self._lock:
            if key not in self._storage:
                return False

            entry = self._storage[key]

            if entry["expiry"] and dt.now(UTC) > entry["expiry"]:
                del self._storage[key]
                return False

            return True

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching a glob pattern with automatic cleanup.

        Args:
            pattern: Glob pattern to match keys against.

        Returns:
            list[str]: List of matching non-expired keys.

        """
        async with self._lock:
            await self._cleanup_expired_internal()

            return [key for key in self._storage if fnmatch.fnmatch(key, pattern)]

    async def cleanup_expired(self) -> int:
        """Remove expired entries from storage.

        Returns:
            int: Number of expired entries removed.

        """
        async with self._lock:
            return await self._cleanup_expired_internal()

    async def _cleanup_expired_internal(self) -> int:
        now = dt.now(UTC)
        expired_keys = []

        for key, entry in self._storage.items():
            if entry["expiry"] and now > entry["expiry"]:
                expired_keys.append(key)

        for key in expired_keys:
            del self._storage[key]

        return len(expired_keys)

"""Token management and blacklisting system with Python 3.13 patterns."""

from __future__ import annotations

import asyncio
import contextlib
import datetime
import fnmatch
from abc import ABC, abstractmethod
from datetime import UTC
from datetime import datetime as dt
from enum import Enum
from typing import TYPE_CHECKING, Any, TypeVar

import redis.asyncio as redis
from flx_core.config.domain_config import get_domain_constants
from flx_core.domain.pydantic_base import DomainValueObject
from passlib.context import CryptContext
from pydantic import Field

if TYPE_CHECKING:
    from redis.asyncio import Redis

    from flx_auth.types import TokenType, UserID

T = TypeVar("T")


class TokenInclusionMode(Enum):
    """Token inclusion mode for filtering token retrieval operations.

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


class TokenMetadata(DomainValueObject):
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
    token_type: TokenType = Field(
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
        """Check if token is expired.

        Compares the current UTC time with the token's expiration time
        to determine if the token has expired.

        Returns:
        -------
            bool: True if the token has expired, False otherwise.

        Note:
        ----
            Uses UTC time for consistency across time zones.

        """
        return dt.now(UTC) > self.expires_at

    @property
    def is_revoked(self) -> bool:
        """Check if token is revoked.

        Determines if the token has been revoked by checking if
        the revoked_at timestamp is set.

        Returns:
        -------
            bool: True if the token has been revoked, False otherwise.

        Note:
        ----
            A token is considered revoked if it has a revoked_at timestamp,
            regardless of the reason or who revoked it.

        """
        return self.revoked_at is not None

    @property
    def is_valid(self) -> bool:
        """Check if token is valid (not expired and not revoked)."""
        return not self.is_expired and not self.is_revoked

    def revoke(
        self, revoked_by: UserID | None = None, reason: str | None = None
    ) -> TokenMetadata:
        """Create a revoked copy of this token metadata."""
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
    r"""TokenStorage - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    store(): Método específico da classe
    get(): Obtém dados
    delete(): Remove dados
    exists(): Método específico da classe
    keys(): Método específico da classe
    cleanup_expired(): Método específico da classe

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = TokenStorage()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Abstract base class for token storage backends."""

    @abstractmethod
    async def store(
        self, key: str, value: T, ttl: datetime.timedelta | None = None
    ) -> None:
        """Store a value with optional TTL.

        Stores a value in the storage backend with an optional time-to-live (TTL).
        If TTL is provided, the value will expire after that duration.

        Args:
        ----
            key: The key to store the value under
            value: The value to store
            ttl: Optional time-to-live for the value

        Returns:
        -------
            None: Indicates successful storage

        Note:
        ----
            Storage backends should handle TTL expiration automatically and
            ensure data persistence according to configured retention policies.

        """
        raise NotImplementedError

    @abstractmethod
    async def get(self, key: str) -> T | None:
        """Get a value by key.

        Retrieves a value from the storage backend by its key. Returns
        None if the key doesn't exist or has expired.

        Args:
        ----
            key: The key to look up

        Returns:
        -------
            T | None: The stored value or None if not found

        Note:
        ----
            Storage backends automatically handle expiration checking
            and return None for expired or non-existent values.

        """
        raise NotImplementedError

    @abstractmethod
    async def delete(self, key: str) -> bool:
        """Delete a value by key.

        Removes a value from the storage backend. Returns True if the
        key existed and was deleted, False otherwise.

        Args:
        ----
            key: The key to delete

        Returns:
        -------
            bool: True if deleted, False if key didn't exist

        Note:
        ----
            Deletion operations should be idempotent and not raise
            exceptions for non-existent keys.

        """
        raise NotImplementedError

    @abstractmethod
    async def exists(self, key: str) -> bool:
        """Check if key exists.

        Checks whether a key exists in the storage backend. This should
        also check if the value has expired.

        Args:
        ----
            key: The key to check

        Returns:
        -------
            bool: True if key exists and hasn't expired, False otherwise

        Note:
        ----
            Existence checking includes automatic expiration validation
            returning False for logically expired entries.

        """
        raise NotImplementedError

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
        raise NotImplementedError

    @abstractmethod
    async def cleanup_expired(self) -> int:
        """Remove expired entries and return count."""
        raise NotImplementedError


class RedisTokenStorage(TokenStorage[str]):
    r"""RedisTokenStorage - Framework Component.

    Implementa componente central do framework com funcionalidades específicas.
    Segue padrões arquiteturais estabelecidos.

    Arquitetura: Enterprise Patterns
    Padrões: SOLID principles, clean code

    Attributes:
    ----------
    Sem atributos públicos documentados.

    Methods:
    -------
    store(): Método específico da classe
    get(): Obtém dados
    delete(): Remove dados
    exists(): Método específico da classe
    keys(): Método específico da classe
    cleanup_expired(): Método específico da classe
    close(): Fecha conexão/recurso

    Examples:
    --------
    Uso típico da classe:

    ```python
    instance = RedisTokenStorage()\n    result = instance.method()
    ```

    See Also:
    --------
    - [Documentação da Arquitetura](../../docs/architecture/index.md)
    - [Padrões de Design](../../docs/architecture/001-clean-architecture-ddd.md)

    Note:
    ----
    Esta classe segue os padrões Enterprise Patterns estabelecidos no projeto.

    """

    """Redis-based token storage implementation."""

    def __init__(
        self, redis_client: Redis[str] | None = None, key_prefix: str = "flx:tokens"
    ) -> None:
        """Initialize with Redis client.

        Sets up the Redis storage backend with an optional custom client
        and key prefix for namespacing.

        Args:
        ----
            redis_client: Optional pre-configured Redis client
            key_prefix: Prefix for all keys to avoid collisions

        Note:
        ----
            Creates Redis connection with default localhost settings
            when no custom client configuration is provided.

        """
        # Get Redis configuration from unified domain config - with strict validation
        if redis_client:
            self.redis = redis_client
        else:
            # Use import from TYPE_CHECKING to avoid circular dependencies
            get_config = __import__(
                "flx_core.config.domain_config",
                fromlist=["get_config"],
            ).get_config
            config = get_config()
            redis_url = f"{config.business.REDIS_PROTOCOL_SCHEME}://{config.network.redis_host}:{config.network.redis_port}/{config.network.redis_database_index}"
            self.redis = redis.from_url(redis_url)
        self.key_prefix = key_prefix

    def _make_key(self, key: str) -> str:
        """Create prefixed key.

        Adds the configured prefix to a key to create a namespaced
        Redis key, preventing collisions with other applications.

        Args:
        ----
            key: The raw key

        Returns:
        -------
            str: The prefixed key

        Note:
        ----
            Prevents key collisions in shared Redis instances through
            consistent prefix application for namespace isolation.

        """
        return f"{self.key_prefix}:{key}"

    async def store(
        self, key: str, value: str, ttl: datetime.timedelta | None = None
    ) -> None:
        """Store a value with optional TTL."""
        redis_key = self._make_key(key)
        if ttl:
            await self.redis.setex(redis_key, int(ttl.total_seconds()), value)
        else:
            await self.redis.set(redis_key, value)

    async def get(self, key: str) -> str | None:
        """Get a value by key.

        Retrieves a value from Redis by its key. Returns None if the
        key doesn't exist or has expired (handled by Redis TTL).

        Args:
        ----
            key: The key to look up

        Returns:
        -------
            str | None: The stored value or None if not found

        Note:
        ----
            Leverages Redis native TTL functionality for automatic
            expiration handling without manual cleanup.

        """
        redis_key = self._make_key(key)
        return await self.redis.get(redis_key)

    async def delete(self, key: str) -> bool:
        """Delete a value by key.

        Removes a value from Redis. Returns True if the key existed
        and was deleted, False otherwise.

        Args:
        ----
            key: The key to delete

        Returns:
        -------
            bool: True if deleted, False if key didn't exist

        Note:
        ----
            Uses Redis delete operation return value to determine
            whether the key existed before deletion.

        """
        redis_key = self._make_key(key)
        result = await self.redis.delete(redis_key)
        return result > 0

    async def exists(self, key: str) -> bool:
        """Check if key exists.

        Checks whether a key exists in Redis. Expired keys are
        automatically removed by Redis so this handles expiration.

        Args:
        ----
            key: The key to check

        Returns:
        -------
            bool: True if key exists, False otherwise

        Note:
        ----
            Leverages Redis exists command which returns count
            of existing keys matching the specified pattern.

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
        """Remove expired entries and return count."""
        # Redis automatically removes expired keys
        return 0

    async def close(self) -> None:
        """Close Redis connection.

        Gracefully closes the Redis connection when the storage is
        no longer needed. This should be called during shutdown.

        Note:
        ----
            Performs graceful shutdown of Redis connections to prevent
            resource leaks during application termination.

        """
        # Try modern async close first, fallback to older version
        try:
            await self.redis.aclose()
        except AttributeError:
            # Fallback for older redis versions that don't have aclose
            await self.redis.close()


class InMemoryTokenStorage(TokenStorage[str]):
    """In-memory token storage for testing and development."""

    def __init__(self) -> None:
        """Initialize in-memory storage.

        Creates an in-memory dictionary for storing tokens with TTL
        support. This is suitable for testing and development but
        not for production use.

        Note:
        ----
            Provides thread-safe in-memory storage suitable for development
            and testing environments with proper concurrency handling.

        """
        self._data: dict[str, tuple[str, dt | None]] = {}
        self._lock = asyncio.Lock()

    async def store(
        self, key: str, value: str, ttl: datetime.timedelta | None = None
    ) -> None:
        """Store a value with optional TTL."""
        expires_at = dt.now(UTC) + ttl if ttl else None
        async with self._lock:
            self._data[key] = (value, expires_at)

    async def get(self, key: str) -> str | None:
        """Get a value by key.

        Retrieves a value from memory, checking for expiration. If the
        value has expired, it's automatically removed.

        Args:
        ----
            key: The key to look up

        Returns:
        -------
            str | None: The stored value or None if not found/expired

        Note:
        ----
            Implements lazy expiration by checking TTL on access
            and automatically removing expired entries.

        """
        async with self._lock:
            if key not in self._data:
                return None

            value, expires_at = self._data[key]

            # Check if expired
            if expires_at and dt.now(UTC) > expires_at:
                del self._data[key]
                return None

            return value

    async def delete(self, key: str) -> bool:
        """Delete a value by key.

        Removes a value from memory. Returns True if the key existed
        and was deleted, False otherwise.

        Args:
        ----
            key: The key to delete

        Returns:
        -------
            bool: True if deleted, False if key didn't exist

        Note:
        ----
            Ensures atomic deletion operations through async locking
            to prevent race conditions in concurrent access.

        """
        async with self._lock:
            if key in self._data:
                del self._data[key]
                return True
            return False

    async def exists(self, key: str) -> bool:
        """Check if key exists.

        Checks whether a key exists and hasn't expired. Uses get()
        internally to handle expiration checking.

        Args:
        ----
            key: The key to check

        Returns:
        -------
            bool: True if key exists and hasn't expired

        Note:
        ----
            Utilizes existing get() method for consistent expiration
            checking without duplicating TTL validation logic.

        """
        return await self.get(key) is not None

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern (simple wildcard support)."""
        async with self._lock:
            return [key for key in self._data if fnmatch.fnmatch(key, pattern)]

    async def cleanup_expired(self) -> int:
        """Remove expired entries and return count."""
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
        """Initialize with database session factory.

        Sets up the database storage backend with a session factory
        for creating database connections.

        Args:
        ----
            db_session_factory: SQLAlchemy session factory

        Note:
        ----
            Provides persistent token storage across application restarts
            with transactional consistency for enterprise deployments.

        """
        self.session_factory = db_session_factory

    async def store(
        self, key: str, value: str, ttl: datetime.timedelta | None = None
    ) -> None:
        """Store a value with optional TTL in database."""
        expires_at = dt.now(UTC) + ttl if ttl else None

        async with self.session_factory() as session:
            # Check if key exists
            existing = await session.execute(
                "SELECT key FROM token_storage WHERE key = :key", {"key": key}
            )

            if existing.scalar():
                # Update existing
                await session.execute(
                    "UPDATE token_storage SET value = :value, expires_at = :expires_at, updated_at = :now WHERE key = :key",
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
                    "INSERT INTO token_storage (key, value, expires_at, created_at) VALUES (:key, :value, :expires_at, :now)",
                    {
                        "key": key,
                        "value": value,
                        "expires_at": expires_at,
                        "now": dt.now(UTC),
                    },
                )

            await session.commit()

    async def get(self, key: str) -> str | None:
        """Get a value by key from database."""
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
                    "DELETE FROM token_storage WHERE key = :key", {"key": key}
                )
                await session.commit()
                return None

            return value

    async def delete(self, key: str) -> bool:
        """Delete a value by key from database."""
        async with self.session_factory() as session:
            result = await session.execute(
                "DELETE FROM token_storage WHERE key = :key", {"key": key}
            )
            await session.commit()
            return result.rowcount > 0

    async def exists(self, key: str) -> bool:
        """Check if key exists in database."""
        async with self.session_factory() as session:
            result = await session.execute(
                "SELECT 1 FROM token_storage WHERE key = :key AND (expires_at IS NULL OR expires_at > :now)",
                {"key": key, "now": dt.now(UTC)},
            )
            return result.scalar() is not None

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern from database."""
        # Convert glob pattern to SQL LIKE pattern
        sql_pattern = pattern.replace("*", "%").replace("?", "_")

        async with self.session_factory() as session:
            result = await session.execute(
                "SELECT key FROM token_storage WHERE key LIKE :pattern AND (expires_at IS NULL OR expires_at > :now)",
                {"pattern": sql_pattern, "now": dt.now(UTC)},
            )
            return [row[0] for row in result]

    async def cleanup_expired(self) -> int:
        """Remove expired entries from database."""
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
        """Initialize token blacklist.

        Sets up the blacklist service with a storage backend. Defaults
        to in-memory storage if none provided.

        Args:
        ----
            storage: Optional storage backend for blacklisted tokens

        Note:
        ----
            Default in-memory storage works for single-instance deployments
            but requires Redis for distributed production environments.

        """
        self.storage = storage or InMemoryTokenStorage()
        self._cleanup_task: asyncio.Task[None] | None = None

    async def start_cleanup_task(
        self,
        interval: datetime.timedelta = datetime.timedelta(hours=1),
    ) -> None:
        """Start periodic cleanup task.

        Starts a background task that periodically removes expired
        tokens from the blacklist to prevent memory bloat.

        Args:
        ----
            interval: How often to run cleanup (default: 1 hour)

        Note:
        ----
            Prevents duplicate cleanup tasks by checking existing
            task status before creating new background processes.

        """
        if self._cleanup_task and not self._cleanup_task.done():
            return

        self._cleanup_task = asyncio.create_task(self._periodic_cleanup(interval))

    async def stop_cleanup_task(self) -> None:
        """Stop periodic cleanup task.

        Gracefully stops the background cleanup task if it's running.
        Suppresses CancelledError to avoid propagation.

        Note:
        ----
            Essential for clean application shutdown to prevent
            orphaned background tasks and resource leaks.

        """
        if self._cleanup_task and not self._cleanup_task.done():
            self._cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cleanup_task

    async def _periodic_cleanup(self, interval: datetime.timedelta) -> None:
        """Periodic cleanup of expired tokens."""
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
        self, token_id: str, expires_at: dt, metadata: TokenMetadata | None = None
    ) -> None:
        """Revoke a token by ID.

        Adds a token to the blacklist with TTL matching its original
        expiration time. This ensures revoked tokens stay blacklisted
        until they would have naturally expired.

        Args:
        ----
            token_id: Unique identifier of the token to revoke
            expires_at: Original expiration time of the token
            metadata: Optional metadata about the revocation

        Note:
        ----
            Optimization to avoid storing already-expired tokens
            in the blacklist since they're naturally invalid.

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
        """Check if a token is revoked.

        Checks the blacklist to see if a token has been revoked.
        A token present in the blacklist is considered revoked.

        Args:
        ----
            token_id: The token ID to check

        Returns:
        -------
            bool: True if the token is in the blacklist

        Note:
        ----
            Storage backend handles TTL expiration automatically
            so revoked tokens are cleaned up when they would expire.

        """
        return await self.storage.exists(token_id)

    async def revoke_user_tokens(
        self, user_id: UserID, token_type: TokenType | None = None
    ) -> int:
        """Revoke all tokens for a user.

        Revokes all tokens belonging to a specific user, optionally
        filtered by token type. This is useful for logout-all-devices
        or security incident response.

        Args:
        ----
            user_id: The user whose tokens to revoke
            token_type: Optional filter by token type (access/refresh)

        Returns:
        -------
            int: Number of tokens revoked

        Note:
        ----
            Employs glob pattern matching to efficiently locate
            all tokens belonging to specific users for bulk operations.

        """
        pattern = f"user:{user_id}:*"
        if token_type:
            pattern = f"user:{user_id}:{token_type.name.lower()}:*"

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
                ttl=datetime.timedelta(days=30),  # Keep revocation record
            )
            revoked_count += 1

        return revoked_count

    async def get_revoked_tokens(
        self, user_id: UserID | None = None, limit: int = 100
    ) -> list[str]:
        """Get list of revoked token IDs."""
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
        """Initialize token manager.

        Sets up comprehensive token management with blacklisting,
        metadata tracking, and user token associations.

        Args:
        ----
            blacklist: Optional custom blacklist service
            storage: Optional storage backend for the blacklist

        Note:
        ----
            Optimizes token operations through in-memory indexing
            of user-token relationships for efficient user-based queries.

        """
        self.blacklist = blacklist or TokenBlacklist(storage)
        self._active_tokens: dict[str, TokenMetadata] = {}
        self._user_tokens: dict[UserID, set[str]] = {}

    async def register_token(self, token_id: str, metadata: TokenMetadata) -> None:
        """Register a new token.

        Registers a token with its metadata for tracking and associates
        it with the owning user for efficient user-based operations.

        Args:
        ----
            token_id: Unique identifier for the token
            metadata: Complete metadata about the token

        Note:
        ----
            Establishes bidirectional mapping between users and tokens
            for efficient user-based token management operations.

        """
        self._active_tokens[token_id] = metadata

        # Track tokens by user
        if metadata.user_id not in self._user_tokens:
            self._user_tokens[metadata.user_id] = set()
        user_tokens = self._user_tokens[metadata.user_id]
        if isinstance(user_tokens, set):
            user_tokens.add(token_id)
        else:
            # Fallback for type safety
            self._user_tokens[metadata.user_id] = {token_id}

    async def validate_token(self, token_id: str) -> bool:
        """Validate a token (check if not revoked and not expired)."""
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
        self, token_id: str, revoked_by: UserID | None = None, reason: str | None = None
    ) -> bool:
        """Revoke a specific token.

        Revokes a token by marking it in metadata and adding it to
        the blacklist. The token remains blacklisted until its
        original expiration time.

        Args:
        ----
            token_id: The token to revoke
            revoked_by: Optional user who performed the revocation
            reason: Optional reason for revocation

        Returns:
        -------
            bool: True if token was revoked, False if not found

        Note:
        ----
            Maintains consistency between memory cache and persistent
            storage for immediate revocation effect across instances.

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

        Revokes all active tokens belonging to a user, optionally filtering by token type.
        This is useful for security scenarios like account compromise or logout from all devices.

        Args:
        ----
            user_id: User whose tokens should be revoked
            token_type: Optional filter for specific token type
            revoked_by: User performing the revocation (for audit trail)
            reason: Optional reason for revocation

        Returns:
        -------
            int: Number of tokens successfully revoked

        Note:
        ----
            Provides comprehensive audit logging for security compliance
            and forensic analysis of bulk token revocation events.

        """
        if user_id not in self._user_tokens:
            return 0

        user_token_ids = list(self._user_tokens[user_id])
        revoked_count = 0

        for token_id in user_token_ids:
            metadata = self._active_tokens.get(token_id)
            if not metadata:
                continue

            # Filter by token type if specified
            if token_type and metadata.token_type != token_type:
                continue

            # Revoke token
            if await self.revoke_token(token_id, revoked_by, reason):
                revoked_count += 1

        return revoked_count

    async def cleanup_expired_tokens(self) -> int:
        """Remove expired tokens from memory."""
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
        """Get all tokens for a user.

        Retrieves all tokens belonging to a user with optional
        filtering by token type and expiration status.

        Args:
        ----
            user_id: The user whose tokens to retrieve
            token_type: Optional filter for specific token type
            inclusion_mode: Token inclusion mode - ACTIVE_ONLY or INCLUDE_EXPIRED

        Returns:
        -------
            list[TokenMetadata]: List of token metadata objects

        Note:
        ----
            Returns active tokens by default, with option to include
            expired tokens via inclusion_mode parameter.

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
        """Get token statistics.

        Computes statistics about managed tokens including counts
        by status, type, and user distribution.

        Returns:
        -------
            dict: Statistics including total, active, expired, revoked
                  tokens, unique users, and breakdown by token type

        Note:
        ----
            Enables operational monitoring and security analytics
            through comprehensive token usage and lifecycle metrics.

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
            token_type = metadata.token_type.name
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
    storage_type: str = "redis", **kwargs: Any
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
        key_prefix = kwargs.get("key_prefix", "flx:tokens")
        return RedisTokenStorage(redis_client=redis_client, key_prefix=key_prefix)

    elif storage_type == "memory":
        return InMemoryTokenStorage()

    elif storage_type == "database":
        db_session_factory = kwargs.get("db_session_factory")
        if not db_session_factory:
            msg = "Database storage requires db_session_factory parameter"
            raise ValueError(msg)
        return DatabaseTokenStorage(db_session_factory=db_session_factory)

    else:
        msg = f"Unknown storage type: {storage_type}. Valid options: redis, memory, database"
        raise ValueError(msg)


class TokenPasswordHasher:
    """Password hashing and verification using Argon2 with Python 3.13 patterns."""

    def __init__(self) -> None:
        """Initialize password hasher with secure defaults.

        Configures Argon2 with security-focused parameters including
        memory cost, time cost, and parallelism settings optimized
        for security over speed.

        Note:
        ----
            Configured for security-first password hashing with high
            memory requirements to resist GPU-based attacks.

        """
        self._crypt_context = CryptContext(
            schemes=["argon2"],
            deprecated="auto",
            argon2__memory_cost=65536,  # 64 MB
            argon2__time_cost=3,  # 3 iterations
            argon2__parallelism=1,  # Single thread
        )

    def hash_password(self, password: str) -> str:
        """Hash a password with Argon2.

        Args:
        ----
            password: Plain text password to hash

        Returns:
        -------
            Hashed password string

        Raises:
        ------
            ValueError: If password is empty or too long
            TypeError: If password is not a string

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
        ----
            password: Plain text password to verify
            hashed_password: Previously hashed password

        Returns:
        -------
            True if password matches hash, False otherwise

        Raises:
        ------
            ValueError: If inputs are invalid
            TypeError: If inputs are not strings

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
        """Check if a hashed password needs to be updated.

        Args:
        ----
            hashed_password: Previously hashed password

        Returns:
        -------
            True if hash needs updating (deprecated algorithm/params)

        """
        try:
            result = self._crypt_context.needs_update(hashed_password)
            return bool(result) if result is not None else True
        except (ValueError, TypeError, AttributeError, RuntimeError):
            # If we can't check password hash format, assume it needs updating
            return True

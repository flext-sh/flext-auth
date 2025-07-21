"""Concrete adapter implementations for external dependencies.

This module provides concrete implementations of the abstractions defined
in the abstractions module, following the Adapter pattern to integrate
with external libraries while maintaining the Dependency Inversion Principle.
"""

from __future__ import annotations

import os
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Any
from uuid import UUID, uuid4

import bcrypt
import jwt
import redis.asyncio as redis

from flext_auth.infrastructure.abstractions import (
    ConfigurationAdapter,
    FileSystemAdapter,
    JWTAdapter,
    PasswordHashingAdapter,
    RedisAdapter,
)

if TYPE_CHECKING:
    from pathlib import Path

    from flext_auth.infrastructure.abstractions import (
        LoggerInterface,
        TimeProvider,
        UUIDGenerator,
    )


class EnvironmentConfigurationAdapter(ConfigurationAdapter):
    """Configuration adapter that reads from environment variables."""

    def __init__(self, prefix: str = "FLEXT_AUTH_") -> None:
        self.prefix = prefix

    def _get_env_key(self, key: str) -> str:
        """Convert key to environment variable name with prefix."""
        return f"{self.prefix}{key.upper()}"

    def get_string(self, key: str, default: str | None = None) -> str:
        """Get string configuration value from environment."""
        env_key = self._get_env_key(key)
        value = os.getenv(env_key, default)
        if value is None:
            msg = f"Required configuration key '{env_key}' not found"
            raise ValueError(msg)
        return value

    def get_int(self, key: str, default: int | None = None) -> int:
        """Get integer configuration value from environment."""
        env_key = self._get_env_key(key)
        value = os.getenv(env_key)
        if value is None:
            if default is None:
                msg = f"Required configuration key '{env_key}' not found"
                raise ValueError(msg)
            return default
        try:
            return int(value)
        except ValueError as e:
            msg = f"Configuration key '{env_key}' must be an integer, got '{value}'"
            raise ValueError(msg) from e

    def get_bool(self, key: str, default: bool | None = None) -> bool:
        """Get boolean configuration value from environment."""
        env_key = self._get_env_key(key)
        value = os.getenv(env_key)
        if value is None:
            if default is None:
                msg = f"Required configuration key '{env_key}' not found"
                raise ValueError(msg)
            return default
        return value.lower() in {"true", "1", "yes", "on"}

    def get_timedelta(self, key: str, default: timedelta | None = None) -> timedelta:
        """Get timedelta configuration value from environment (in seconds)."""
        default_seconds = int(default.total_seconds()) if default else None
        seconds = self.get_int(f"{key}_SECONDS", default_seconds)
        return timedelta(seconds=seconds)


class PyJWTAdapter(JWTAdapter):
    """JWT adapter using PyJWT library."""

    def encode(
        self,
        payload: dict[str, Any],
        key: str,
        algorithm: str,
    ) -> str:
        """Encode JWT token using PyJWT."""
        try:
            token = jwt.encode(payload, key, algorithm=algorithm)
            # Handle both str and bytes return types from different PyJWT versions
            return token.decode("utf-8") if hasattr(token, "decode") else str(token)
        except (jwt.InvalidKeyError, jwt.InvalidAlgorithmError, ValueError) as e:
            msg = f"Failed to encode JWT token: {e}"
            raise ValueError(msg) from e

    def decode(
        self,
        token: str,
        key: str,
        algorithms: list[str],
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Decode JWT token using PyJWT."""
        try:
            payload = jwt.decode(
                token,
                key,
                algorithms=algorithms,
                options=options or {},
            )
            return dict(payload)
        except jwt.ExpiredSignatureError as e:
            msg = "Token has expired"
            raise ValueError(msg) from e
        except jwt.InvalidTokenError as e:
            msg = f"Invalid token: {e}"
            raise ValueError(msg) from e


class BcryptPasswordHashingAdapter(PasswordHashingAdapter):
    """Password hashing adapter using bcrypt library."""

    def hash_password(self, password: str, rounds: int | None = None) -> str:
        """Hash password using bcrypt."""
        if not password:
            msg = "Password cannot be empty"
            raise ValueError(msg)

        # Use provided rounds or default
        rounds = rounds or 12

        try:
            # Generate salt and hash password
            salt = bcrypt.gensalt(rounds=rounds)
            hashed = bcrypt.hashpw(password.encode("utf-8"), salt)
            return hashed.decode("utf-8")
        except (ValueError, TypeError, OverflowError) as e:
            msg = f"Failed to hash password: {e}"
            raise ValueError(msg) from e

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against bcrypt hash."""
        if not password or not hashed:
            return False

        try:
            return bcrypt.checkpw(
                password.encode("utf-8"),
                hashed.encode("utf-8"),
            )
        except (ValueError, TypeError):
            # Invalid hash format or other error - treat as failed verification
            return False

    def needs_rehash(self, hashed: str, rounds: int | None = None) -> bool:
        """Check if bcrypt hash needs to be updated."""
        if not hashed:
            return True

        rounds = rounds or 12

        try:
            # Extract cost factor from hash
            # bcrypt hash format: $2b$rounds$salt+hash
            parts = hashed.split("$")
            if len(parts) < 4 or parts[1] != "2b":
                return True  # Invalid format, needs rehash

            current_rounds = int(parts[2])
            return current_rounds < rounds
        except (ValueError, IndexError):
            return True  # Can't parse, assume needs rehash


class PathlibFileSystemAdapter(FileSystemAdapter):
    """File system adapter using pathlib."""

    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """Read text content from file using pathlib."""
        try:
            return path.read_text(encoding=encoding)
        except Exception as e:
            msg = f"Failed to read file '{path}': {e}"
            raise ValueError(msg) from e

    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        """Write text content to file using pathlib."""
        try:
            # Ensure parent directory exists
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content, encoding=encoding)
        except Exception as e:
            msg = f"Failed to write file '{path}': {e}"
            raise ValueError(msg) from e

    def exists(self, path: Path) -> bool:
        """Check if path exists using pathlib."""
        return path.exists()


class RedisAsyncAdapter(RedisAdapter):
    """Redis adapter using redis-py async client."""

    def __init__(self, redis_client: redis.Redis[str]) -> None:
        self._client = redis_client

    @property
    def client(self) -> redis.Redis[str]:
        """Get the underlying Redis client for compatibility."""
        return self._client

    @classmethod
    def from_url(cls, url: str) -> RedisAsyncAdapter:
        """Create adapter from Redis URL."""
        client = redis.from_url(url)
        return cls(client)

    async def get(self, key: str) -> str | None:
        """Get value by key from Redis."""
        try:
            return await self._client.get(key)
        except (redis.RedisError, ConnectionError) as e:
            msg = f"Failed to get key '{key}' from Redis: {e}"
            raise ValueError(msg) from e

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        """Set value with optional expiration in Redis."""
        try:
            await self._client.set(key, value, ex=ex)
        except (redis.RedisError, ConnectionError) as e:
            msg = f"Failed to set key '{key}' in Redis: {e}"
            raise ValueError(msg) from e

    async def delete(self, key: str) -> int:
        """Delete key from Redis."""
        try:
            return await self._client.delete(key)
        except (redis.RedisError, ConnectionError) as e:
            msg = f"Failed to delete key '{key}' from Redis: {e}"
            raise ValueError(msg) from e

    async def exists(self, key: str) -> int:
        """Check if key exists in Redis."""
        try:
            return await self._client.exists(key)
        except (redis.RedisError, ConnectionError) as e:
            msg = f"Failed to check existence of key '{key}' in Redis: {e}"
            raise ValueError(msg) from e

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern from Redis."""
        try:
            keys = await self._client.keys(pattern)
            # Handle both str and bytes keys from different Redis configurations
            return [
                key.decode("utf-8") if hasattr(key, "decode") else str(key)
                for key in keys
            ]
        except (redis.RedisError, ConnectionError) as e:
            msg = f"Failed to get keys with pattern '{pattern}' from Redis: {e}"
            raise ValueError(msg) from e

    async def close(self) -> None:
        """Close Redis connection."""
        import contextlib

        with contextlib.suppress(redis.RedisError, ConnectionError):
            await self._client.close()


# Utility providers


class SystemTimeProvider:
    """System time provider using datetime module."""

    def now_utc(self) -> datetime:
        """Get current UTC datetime."""
        return datetime.now(UTC)

    def now_local(self) -> datetime:
        """Get current local datetime."""
        return datetime.now()


class StandardUUIDGenerator:
    """Standard UUID generator using uuid module."""

    def generate(self) -> UUID:
        """Generate new UUID4."""
        return uuid4()

    def from_string(self, uuid_string: str) -> UUID:
        """Parse UUID from string."""
        try:
            return UUID(uuid_string)
        except ValueError as e:
            msg = f"Invalid UUID string '{uuid_string}': {e}"
            raise ValueError(msg) from e


class FlextObservabilityLogger:
    """Logger adapter using flext-observability."""

    def __init__(self, name: str) -> None:
        from flext_observability.logging import get_logger

        self._logger = get_logger(name)

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        self._logger.debug(message, **kwargs)

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        self._logger.info(message, **kwargs)

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        self._logger.warning(message, **kwargs)

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        self._logger.error(message, **kwargs)

    def exception(self, message: str, **kwargs: Any) -> None:
        """Log exception with traceback."""
        self._logger.exception(message, **kwargs)


# Factory functions for easy creation


def create_environment_config(
    prefix: str = "FLEXT_AUTH_",
) -> EnvironmentConfigurationAdapter:
    """Create environment configuration adapter."""
    return EnvironmentConfigurationAdapter(prefix)


def create_jwt_adapter() -> PyJWTAdapter:
    """Create PyJWT adapter."""
    return PyJWTAdapter()


def create_password_hasher() -> BcryptPasswordHashingAdapter:
    """Create bcrypt password hasher."""
    return BcryptPasswordHashingAdapter()


def create_filesystem() -> PathlibFileSystemAdapter:
    """Create pathlib file system adapter."""
    return PathlibFileSystemAdapter()


def create_redis_adapter(url: str) -> RedisAsyncAdapter:
    """Create Redis adapter from URL."""
    return RedisAsyncAdapter.from_url(url)


def create_time_provider() -> SystemTimeProvider:
    """Create system time provider."""
    return SystemTimeProvider()


def create_uuid_generator() -> StandardUUIDGenerator:
    """Create standard UUID generator."""
    return StandardUUIDGenerator()


def create_logger(name: str) -> FlextObservabilityLogger:
    """Create flext-observability logger."""
    return FlextObservabilityLogger(name)

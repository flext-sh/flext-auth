"""Dependency Inversion Principle abstractions for flext-auth infrastructure.

This module provides abstract interfaces for external dependencies to decouple
the infrastructure layer from concrete implementations, following the
Dependency Inversion Principle.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, Any, Protocol

if TYPE_CHECKING:
    from datetime import timedelta
    from pathlib import Path


class ConfigurationProvider(Protocol):
    """Abstract configuration provider interface.

    Abstracts away configuration sources (environment, files, etc.)
    to decouple components from specific configuration mechanisms.
    """

    def get_string(self, key: str, default: str | None = None) -> str:
        """Get string configuration value."""
        ...

    def get_int(self, key: str, default: int | None = None) -> int:
        """Get integer configuration value."""
        ...

    def get_bool(self, key: str, default: bool | None = None) -> bool:
        """Get boolean configuration value."""
        ...

    def get_timedelta(self, key: str, default: timedelta | None = None) -> timedelta:
        """Get timedelta configuration value."""
        ...


class JWTLibrary(Protocol):
    """Abstract JWT library interface.

    Abstracts JWT operations to decouple from specific JWT implementations
    like PyJWT, allowing for easier testing and library swapping.
    """

    def encode(
        self,
        payload: dict[str, Any],
        key: str,
        algorithm: str,
    ) -> str:
        """Encode JWT token with given payload."""
        ...

    def decode(
        self,
        token: str,
        key: str,
        algorithms: list[str],
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Decode JWT token and return payload."""
        ...


class PasswordHashingLibrary(Protocol):
    """Abstract password hashing library interface.

    Abstracts password hashing operations to decouple from specific
    implementations like bcrypt, argon2, etc.
    """

    def hash_password(self, password: str, rounds: int | None = None) -> str:
        """Hash password with optional rounds parameter."""
        ...

    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        ...

    def needs_rehash(self, hashed: str, rounds: int | None = None) -> bool:
        """Check if password hash needs to be updated."""
        ...


class FileSystemInterface(Protocol):
    """Abstract file system interface.

    Abstracts file system operations to decouple from specific
    file system implementations and enable easier testing.
    """

    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """Read text content from file."""
        ...

    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        """Write text content to file."""
        ...

    def exists(self, path: Path) -> bool:
        """Check if path exists."""
        ...


class RedisInterface(Protocol):
    """Abstract Redis interface.

    Abstracts Redis operations to decouple from specific Redis clients
    and enable easier testing with in-memory implementations.
    """

    async def get(self, key: str) -> str | None:
        """Get value by key."""
        ...

    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        """Set value with optional expiration."""
        ...

    async def delete(self, key: str) -> int:
        """Delete key and return number of deleted keys."""
        ...

    async def exists(self, key: str) -> int:
        """Check if key exists."""
        ...

    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern."""
        ...

    async def close(self) -> None:
        """Close connection."""
        ...


class DatabaseInterface(Protocol):
    """Abstract database interface.

    Abstracts database operations to decouple from specific database
    implementations and ORMs.
    """

    async def execute(self, query: str, params: dict[str, Any] | None = None) -> Any:
        """Execute database query."""
        ...

    async def fetch_one(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> dict[str, Any] | None:
        """Fetch one record."""
        ...

    async def fetch_all(
        self, query: str, params: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        """Fetch all records."""
        ...

    async def begin_transaction(self) -> None:
        """Begin database transaction."""
        ...

    async def commit_transaction(self) -> None:
        """Commit database transaction."""
        ...

    async def rollback_transaction(self) -> None:
        """Rollback database transaction."""
        ...


class LoggerInterface(Protocol):
    """Abstract logger interface.

    Abstracts logging operations to decouple from specific logging
    implementations and enable easier testing.
    """

    def debug(self, message: str, **kwargs: Any) -> None:
        """Log debug message."""
        ...

    def info(self, message: str, **kwargs: Any) -> None:
        """Log info message."""
        ...

    def warning(self, message: str, **kwargs: Any) -> None:
        """Log warning message."""
        ...

    def error(self, message: str, **kwargs: Any) -> None:
        """Log error message."""
        ...

    def exception(self, message: str, **kwargs: Any) -> None:
        """Log exception with traceback."""
        ...


class TimeProvider(Protocol):
    """Abstract time provider interface.

    Abstracts time operations to enable easier testing with
    controllable time sources.
    """

    def now_utc(self) -> datetime:
        """Get current UTC datetime."""
        ...

    def now_local(self) -> datetime:
        """Get current local datetime."""
        ...


class UUIDGenerator(Protocol):
    """Abstract UUID generator interface.

    Abstracts UUID generation to enable easier testing with
    predictable UUIDs.
    """

    def generate(self) -> UUID:
        """Generate new UUID."""
        ...

    def from_string(self, uuid_string: str) -> UUID:
        """Parse UUID from string."""
        ...


# Base classes for adapter implementations


class ConfigurationAdapter(ABC):
    """Base class for configuration adapters."""

    @abstractmethod
    def get_string(self, key: str, default: str | None = None) -> str:
        """Get string configuration value."""

    @abstractmethod
    def get_int(self, key: str, default: int | None = None) -> int:
        """Get integer configuration value."""

    @abstractmethod
    def get_bool(self, key: str, default: bool | None = None) -> bool:
        """Get boolean configuration value."""

    @abstractmethod
    def get_timedelta(self, key: str, default: timedelta | None = None) -> timedelta:
        """Get timedelta configuration value."""


class JWTAdapter(ABC):
    """Base class for JWT adapters."""

    @abstractmethod
    def encode(
        self,
        payload: dict[str, Any],
        key: str,
        algorithm: str,
    ) -> str:
        """Encode JWT token with given payload."""

    @abstractmethod
    def decode(
        self,
        token: str,
        key: str,
        algorithms: list[str],
        options: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Decode JWT token and return payload."""


class PasswordHashingAdapter(ABC):
    """Base class for password hashing adapters."""

    @abstractmethod
    def hash_password(self, password: str, rounds: int | None = None) -> str:
        """Hash password with optional rounds parameter."""

    @abstractmethod
    def verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""

    @abstractmethod
    def needs_rehash(self, hashed: str, rounds: int | None = None) -> bool:
        """Check if password hash needs to be updated."""


class FileSystemAdapter(ABC):
    """Base class for file system adapters."""

    @abstractmethod
    def read_text(self, path: Path, encoding: str = "utf-8") -> str:
        """Read text content from file."""

    @abstractmethod
    def write_text(self, path: Path, content: str, encoding: str = "utf-8") -> None:
        """Write text content to file."""

    @abstractmethod
    def exists(self, path: Path) -> bool:
        """Check if path exists."""


class RedisAdapter(ABC):
    """Base class for Redis adapters."""

    @abstractmethod
    async def get(self, key: str) -> str | None:
        """Get value by key."""

    @abstractmethod
    async def set(self, key: str, value: str, ex: int | None = None) -> None:
        """Set value with optional expiration."""

    @abstractmethod
    async def delete(self, key: str) -> int:
        """Delete key and return number of deleted keys."""

    @abstractmethod
    async def exists(self, key: str) -> int:
        """Check if key exists."""

    @abstractmethod
    async def keys(self, pattern: str) -> list[str]:
        """Get keys matching pattern."""

    @abstractmethod
    async def close(self) -> None:
        """Close connection."""


# Import guard to prevent import errors
if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID

"""Core utilities for flext-auth."""

from __future__ import annotations

from typing import TypeVar

T = TypeVar("T")


class ServiceResult[T]:
    """Service result pattern for clean error handling."""

    def __init__(
        self, success: bool, data: T | None = None, error: str | None = None
    ) -> None:
        """Initialize service result."""
        self._success = success
        self._data = data
        self._error = error

    @property
    def is_success(self) -> bool:
        """Check if operation was successful."""
        return self._success

    @property
    def data(self) -> T | None:
        """Get result data."""
        if not self._success:
            raise ValueError("Cannot access data on failed result")
        return self._data

    @property
    def error(self) -> str:
        """Get error message."""
        if self._success or self._error is None:
            raise ValueError("Cannot access error on successful result")
        return self._error

    @classmethod
    def ok(cls, data: T | None = None) -> ServiceResult[T]:
        """Create successful result."""
        return cls(success=True, data=data)

    @classmethod
    def fail(cls, error: str) -> ServiceResult[T]:
        """Create failed result."""
        return cls(success=False, error=error)

"""Auth application lifecycle helpers."""

from __future__ import annotations

import threading
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, ClassVar, Self

from flext_auth import c, p, t


class FlextAuthApplicationLifecycle(ABC):
    _instance: ClassVar[Self | None] = None
    _lock: ClassVar[threading.Lock] = threading.Lock()

    if TYPE_CHECKING:

        @property
        def logger(self) -> p.Logger:
            """Logger supplied by the service facade."""
            raise NotImplementedError

    @abstractmethod
    def register_user(
        self,
        username: str,
        email: str,
        password: str,
        roles: t.StrSequence | None = None,
        role: str | None = None,
    ) -> p.Result[p.Auth.AuthIdentity]:
        raise NotImplementedError

    @classmethod
    def fetch_global(cls) -> Self:
        """Thread-safe singleton accessor."""
        instance = cls._instance
        if isinstance(instance, cls):
            return instance
        with cls._lock:
            locked_instance = cls._instance
            if isinstance(locked_instance, cls):
                return locked_instance
            instance = cls()
            cls._instance = instance
            return instance

    @classmethod
    def reset_for_testing(cls) -> None:
        """Clear the cached singleton instance for test isolation."""
        with cls._lock:
            cls._instance = None

    @classmethod
    def quick_start(cls, *, create_admin_user: bool = True) -> Self:
        """Quick start factory with default configuration."""
        auth: Self = cls()
        if create_admin_user:
            result = auth.register_user(
                c.Auth.DEFAULT_ADMIN_USERNAME,
                c.Auth.DEFAULT_ADMIN_EMAIL,
                "AdminPass123!",
                roles=["ADMIN"],
            )
            if result.failure and result.error is not None:
                auth.logger.warning(
                    "Quick start admin user provisioning failed: %s", result.error
                )
        return auth


__all__: t.MutableSequenceOf[str] = ["FlextAuthApplicationLifecycle"]

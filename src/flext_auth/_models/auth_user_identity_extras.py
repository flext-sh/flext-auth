"""Authentication user identity extras models."""

from __future__ import annotations

from collections.abc import Sequence
from datetime import UTC, datetime
from typing import ClassVar

from flext_api import m, u

from flext_auth import t


class FlextAuthModelsAuthUserIdentityExtras:
    """Authentication user identity extras model namespace."""

    class UserIdentityExtras(m.BaseModel):
        """Normalized optional extras for identity creation."""

        _MIN_DATETIME: ClassVar[datetime] = datetime.min.replace(tzinfo=UTC)

        full_name: str | None = None
        is_active: bool | None = None
        roles: t.StrSequence | None = None
        permissions: t.StrSequence | None = None
        failed_attempts: int | None = None
        locked_until: datetime | None = None
        last_access: datetime | None = None
        token: str | None = None
        session_id: str | None = None

        @u.field_validator("roles", "permissions", mode="before")
        @classmethod
        def normalize_str_sequence(
            cls,
            value: t.Scalar | t.StrSequence | datetime | None,
        ) -> t.StrSequence | None:
            """Normalize sequence-like values to strict string sequences."""
            if value is None:
                return None
            if isinstance(value, Sequence) and not isinstance(
                value, t.STR_BINARY_TYPES
            ):
                return list(value)
            return []

        @u.field_validator("failed_attempts", mode="before")
        @classmethod
        def normalize_failed_attempts(
            cls,
            value: t.Scalar | t.StrSequence | datetime | None,
        ) -> int | None:
            """Normalize failed attempts from int-like values."""
            if value is None:
                return None
            if isinstance(value, int):
                return max(value, 0)
            if isinstance(value, str) and value.isdigit():
                return int(value)
            return 0

        @u.field_validator("locked_until", "last_access", mode="before")
        @classmethod
        def normalize_datetime(
            cls,
            value: t.Scalar | t.StrSequence | datetime | None,
        ) -> datetime | None:
            """Normalize datetime-like values with deterministic fallback."""
            if value is None:
                return None
            match value:
                case datetime() as datetime_value:
                    return datetime_value
                case str() as datetime_str:
                    try:
                        return datetime.fromisoformat(datetime_str)
                    except ValueError:
                        return cls._MIN_DATETIME
                case _:
                    return cls._MIN_DATETIME


__all__: list[str] = ["FlextAuthModelsAuthUserIdentityExtras"]

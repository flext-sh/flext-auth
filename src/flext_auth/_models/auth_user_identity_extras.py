"""Authentication user identity extras models.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

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
        roles: Sequence[str] | None = None
        permissions: Sequence[str] | None = None
        failed_attempts: int | None = None
        locked_until: datetime | None = None
        last_access: datetime | None = None
        token: str | None = None
        session_id: str | None = None

        @m.field_validator("roles", "permissions", mode="before")
        @classmethod
        def normalize_str_sequence(
            cls,
            value: t.JsonPayload,
        ) -> Sequence[str] | None:
            """Normalize sequence-like values to strict string sequences.

            Args:
                value: Raw input for the ``roles`` or ``permissions`` field.

            Returns:
                The validated string sequence, or ``None`` when absent.

            """
            if value is None:
                return None
            if isinstance(value, (str, bytes, bytearray)):
                return []
            if isinstance(value, Sequence):
                return u.strict_str_sequence_adapter().validate_python(value)
            return []

        @m.field_validator("failed_attempts", mode="before")
        @classmethod
        def normalize_failed_attempts(
            cls,
            value: t.JsonPayload,
        ) -> int | None:
            """Normalize failed attempts from int-like values.

            Args:
                value: Raw input for the ``failed_attempts`` field.

            Returns:
                The non-negative attempt count, or ``None`` when absent.

            """
            if value is None:
                return None
            if isinstance(value, int):
                return max(value, 0)
            if isinstance(value, str) and value.isdigit():
                return int(value)
            return 0

        @m.field_validator("locked_until", "last_access", mode="before")
        @classmethod
        def normalize_datetime(
            cls,
            value: t.JsonPayload,
        ) -> datetime | None:
            """Normalize datetime-like values with deterministic fallback.

            Args:
                value: Raw input for the ``locked_until`` or ``last_access``
                    field.

            Returns:
                The parsed timestamp, or the epoch-sentinel minimum when the
                value cannot be parsed.

            """
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

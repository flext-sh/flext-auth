"""FLEXT Auth Types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    MutableMapping,
    MutableSequence,
)
from datetime import datetime
from typing import Annotated, Literal

from flext_api import t, u

from flext_auth import c


class FlextAuthTypes(t):
    """Authentication-specific type definitions extending t via MRO."""

    class Auth:
        """Auth domain namespace (flat members per AGENTS.md §149)."""

        type TokenRequestType = Literal["access", "refresh", "id", "bearer"]

        type ProvidersKey = Annotated[
            str,
            u.Field(
                min_length=1,
                max_length=c.Auth.Validation.SHORT_NAME_MAX,
                pattern="^[a-z0-9](?:[a-z0-9\\-_.]{0,62}[a-z0-9])?$",
                description="Provider registry key",
            ),
        ]

        type TokensClaimMap = t.MutableJsonMapping

        type ManagersManagerValue = t.JsonValue | t.Scalar | t.StrSequence
        type ManagersUserData = MutableMapping[str, ManagersManagerValue]
        type ManagersLogEntry = MutableMapping[str, ManagersManagerValue]
        type ManagersSessionData = t.MutableMetadataMapping
        type ManagersAttemptEvents = MutableSequence[datetime]
        type ManagersAttemptData = MutableMapping[str, ManagersAttemptEvents]

        STR_SEQUENCE_ADAPTER: u.TypeAdapter[t.StrSequence] = u.TypeAdapter(
            t.StrSequence
        )
        CONTAINER_VALUE_MAPPING_ADAPTER: u.TypeAdapter[t.JsonMapping] = u.TypeAdapter(
            t.JsonMapping
        )


t = FlextAuthTypes

__all__: list[str] = ["FlextAuthTypes", "t"]

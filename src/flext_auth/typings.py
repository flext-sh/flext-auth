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
from typing import Annotated

from flext_api import t, u

from flext_auth import c


class FlextAuthTypes(t):
    """Authentication-specific type definitions extending t via MRO."""

    class Auth:
        """Auth domain namespace (flat members per AGENTS.md §149)."""

        type TokenRequestType = c.Auth.TokenTypes | str

        type ProvidersKey = Annotated[
            str,
            u.Field(
                min_length=1,
                max_length=c.Auth.VALIDATION_SHORT_NAME_MAX,
                pattern=c.PATTERN_IDENTIFIER_LOWERCASE,
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


t = FlextAuthTypes

__all__: list[str] = ["FlextAuthTypes", "t"]

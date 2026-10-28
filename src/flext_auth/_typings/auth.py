"""Authentication-focused typed aliases of the FlextAuth typings family.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import (
    Iterable,
    Iterator,
    Mapping,
    MutableMapping,
    MutableSequence,
    Sequence,
)

from collections.abc import Callable, MutableMapping, MutableSequence, Sequence
from typing import TYPE_CHECKING, Annotated

from flext_api import m as api_models, t

from flext_auth import c
from flext_auth._typings import FlextAuthTypesBase

if TYPE_CHECKING:
    from flext_auth import m


class FlextAuthTypesAuth:
    """Internal and manager-facing aliases for authentication workflows."""

    type TokenRequestType = c.Auth.TokenTypes | str
    type ProvidersKey = Annotated[
        str,
        api_models.Field(
            min_length=1,
            max_length=c.Auth.VALIDATION_SHORT_NAME_MAX,
            pattern=c.PATTERN_IDENTIFIER_LOWERCASE,
            description="Provider registry key",
        ),
    ]

    type ManagersManagerValue = t.JsonValue | t.Scalar | Sequence[str]
    type ManagersUserData = MutableMapping[str, ManagersManagerValue]
    type ManagersLogEntry = MutableMapping[str, ManagersManagerValue]
    type ManagersSessionData = t.MutableMetadataMapping
    type ManagersAttemptEvents = MutableSequence[FlextAuthTypesBase.DateTimeValue]
    type ManagersAttemptData = MutableMapping[str, ManagersAttemptEvents]

    type KerberosTicketValidator = Callable[
        [str],
        m.Auth.AuthIdentity | t.JsonMapping | m.Auth.KerberosTicketData,
    ]


__all__: list[str] = ["FlextAuthTypesAuth"]

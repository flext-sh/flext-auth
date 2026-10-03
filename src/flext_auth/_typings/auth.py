"""Authentication-focused typed aliases of the FlextAuth typings family."""

from __future__ import annotations

from collections.abc import Callable, MutableMapping, MutableSequence
from datetime import datetime
from typing import TYPE_CHECKING

from flext_api import t

if TYPE_CHECKING:
    from flext_auth import m


class FlextAuthTypesAuth:
    """Internal and manager-facing aliases for authentication workflows."""

    type ManagersDateTimeValue = datetime
    type ManagersManagerValue = t.JsonValue | t.Scalar | t.StrSequence
    type ManagersUserData = MutableMapping[str, ManagersManagerValue]
    type ManagersLogEntry = MutableMapping[str, ManagersManagerValue]
    type ManagersSessionData = t.MutableMetadataMapping
    type ManagersAttemptEvents = MutableSequence[ManagersDateTimeValue]
    type ManagersAttemptData = MutableMapping[str, ManagersAttemptEvents]

    type KerberosTicketValidator = Callable[
        [str], m.Auth.AuthIdentity | t.JsonMapping | m.Auth.KerberosTicketData
    ]


__all__: list[str] = ["FlextAuthTypesAuth"]

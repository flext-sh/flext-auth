"""FlextAuth typings base — foundational aliases owner of the private family."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from flext_api import t, u

from flext_auth import c


class FlextAuthTypesBase:
    """Base and foundational owner of the FlextAuth private typings family.

    Holds the core scalar aliases every composed ``FlextAuthTypes*`` owner
    inherits, so the family MRO is explicit and the domain namespace composes
    all owners through multiple inheritance.
    """

    type DateTimeValue = datetime
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


__all__: list[str] = ["FlextAuthTypesBase"]

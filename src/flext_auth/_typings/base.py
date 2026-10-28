"""FlextAuth typings base — foundational aliases owner of the private family.

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

from datetime import datetime

from flext_api import t


class FlextAuthTypesBase:
    """Base and foundational owner of the FlextAuth private typings family.

    Holds the core scalar aliases every composed ``FlextAuthTypes*`` owner
    inherits, so the family MRO is explicit and the domain namespace composes
    all owners through multiple inheritance.
    """

    type DateTimeValue = datetime
    type TokensClaimMap = t.MutableJsonMapping


__all__: list[str] = ["FlextAuthTypesBase"]

"""FlextAuth constants base — foundational constants owner of the private family.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Final


class FlextAuthConstantsBase:
    """Base and foundational owner of the FlextAuth private constants family.

    Every composed ``FlextAuthConstants*`` owner inherits from this base, so
    the family MRO is explicit and the domain namespace composes all owners
    through multiple inheritance.
    """

    SECRET_MIN_LENGTH: Final[int] = 32
    "Minimum secret key length."


__all__: list[str] = ["FlextAuthConstantsBase"]

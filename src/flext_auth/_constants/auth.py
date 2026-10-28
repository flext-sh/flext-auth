"""Authentication constants namespace.

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

from flext_auth._constants import FlextAuthConstantsAuthValues


class FlextAuthConstantsAuth(FlextAuthConstantsAuthValues):
    """Authentication constants namespace assembled from focused owners."""


__all__: list[str] = ["FlextAuthConstantsAuth"]

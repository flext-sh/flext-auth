"""Authentication constants namespace values — stand-in for facade MRO composition.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._constants import FlextAuthConstantsAuthSecurity
from flext_auth._constants.values import FlextAuthValues


class FlextAuthConstantsAuthValues(FlextAuthConstantsAuthSecurity, FlextAuthValues):
    """Complete authentication constants namespace via stand-in composition."""

    pass


__all__: list[str] = ["FlextAuthConstantsAuthValues"]

"""Authentication constants namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._constants.auth_values import FlextAuthConstantsAuthValues


class FlextAuthConstantsAuth(FlextAuthConstantsAuthValues):
    """Authentication constants namespace assembled from focused owners."""


__all__: list[str] = ["FlextAuthConstantsAuth"]

# AUTO-GENERATED FILE — Regenerate with: make gen
"""FlextAuth constants facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import FlextApiConstants

from flext_auth._constants import (
    FlextAuthConstantsAuth,
    FlextAuthConstantsAuthClaims,
    FlextAuthConstantsAuthEnums,
    FlextAuthConstantsAuthSecurity,
    FlextAuthConstantsAuthValues,
    FlextAuthConstantsBase,
)


class FlextAuthConstants(FlextApiConstants):
    """FlextAuth domain constants extending the API constants namespace."""

    class Auth(
        FlextAuthConstantsAuth,
        FlextAuthConstantsAuthValues,
        FlextAuthConstantsAuthSecurity,
        FlextAuthConstantsAuthClaims,
        FlextAuthConstantsAuthEnums,
        FlextAuthConstantsBase,
    ):
        """Authentication constants namespace."""


c = FlextAuthConstants
__all__: list[str] = ["FlextAuthConstants", "c"]

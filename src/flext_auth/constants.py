# AUTO-GENERATED FILE — Regenerate with: make gen
"""FlextAuth constants facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_api import FlextApiConstants

from flext_auth._constants import (
    FlextAuthConstantsAuth,
    FlextAuthConstantsAuthClaims,
    FlextAuthConstantsAuthEnums,
    FlextAuthConstantsAuthSecurity,
    FlextAuthConstantsAuthValues,
    FlextAuthConstantsBase,
)

if TYPE_CHECKING:
    from flext_auth import t


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

__all__: t.MutableSequenceOf[str] = ["FlextAuthConstants", "c"]

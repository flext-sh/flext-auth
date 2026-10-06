# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.providers. Mixins package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.providers._mixins.codec import FlextAuthProviderCodecMixin
    from flext_auth.providers._mixins.tokens import FlextAuthProviderTokenMixin
    from flext_auth.providers._mixins.validation import FlextAuthProviderValidationMixin


__all__: tuple[str, ...] = (
    "FlextAuthProviderCodecMixin",
    "FlextAuthProviderTokenMixin",
    "FlextAuthProviderValidationMixin",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthProviderCodecMixin": ".codec",
        "FlextAuthProviderTokenMixin": ".tokens",
        "FlextAuthProviderValidationMixin": ".validation",
    }),
    public_exports=__all__,
)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth.providers. Mixins package.

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

from types import MappingProxyType
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.providers._mixins.codec import FlextAuthProviderCodec
    from flext_auth.providers._mixins.tokens import FlextAuthProviderToken
    from flext_auth.providers._mixins.validation import FlextAuthProviderValidation


__all__: tuple[str, ...] = (
    "FlextAuthProviderCodec",
    "FlextAuthProviderToken",
    "FlextAuthProviderValidation",
)

install_lazy_exports(
    __name__,
    globals(),
    MappingProxyType({
        "FlextAuthProviderCodec": ".codec",
        "FlextAuthProviderToken": ".tokens",
        "FlextAuthProviderValidation": ".validation",
    }),
    public_exports=__all__,
)

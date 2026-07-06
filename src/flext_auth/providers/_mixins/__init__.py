# AUTO-GENERATED FILE — Regenerate with: make gen
"""Mixins package."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import build_lazy_import_map, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth.providers._mixins.codec import FlextAuthProviderCodecMixin
    from flext_auth.providers._mixins.tokens import FlextAuthProviderTokenMixin
    from flext_auth.providers._mixins.validation import FlextAuthProviderValidationMixin
_LAZY_IMPORTS = build_lazy_import_map(
    {
        ".codec": ("FlextAuthProviderCodecMixin",),
        ".tokens": ("FlextAuthProviderTokenMixin",),
        ".validation": ("FlextAuthProviderValidationMixin",),
    },
)


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    publish_all=False,
)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth package."""

from __future__ import annotations

from flext_auth.__version__ import (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
)
from flext_auth._exports import (
    FLEXT_AUTH_LAZY_IMPORTS,
    FLEXT_AUTH_PUBLIC_EXPORTS,
)
from flext_core import d, e, h, r, x
from flext_core.lazy import install_lazy_exports

_LAZY_IMPORTS = {
    name: target
    for name, target in FLEXT_AUTH_LAZY_IMPORTS.items()
    if name in FLEXT_AUTH_PUBLIC_EXPORTS
}


_EAGER_EXPORTS = (
    __author__,
    __author_email__,
    __description__,
    __license__,
    __title__,
    __url__,
    __version__,
    __version_info__,
    d,
    e,
    h,
    r,
    x,
)


_PUBLIC_EXPORTS: tuple[str, ...] = FLEXT_AUTH_PUBLIC_EXPORTS


install_lazy_exports(
    __name__,
    globals(),
    _LAZY_IMPORTS,
    public_exports=_PUBLIC_EXPORTS,
)

# AUTO-GENERATED FILE — Regenerate with: make gen
"""Package version and metadata for flext-auth.

Subclass of ``FlextVersion`` — overrides only ``_metadata``.
All derived attributes (``__version__``, ``__title__``, etc.) are
computed automatically via ``FlextVersion.__init_subclass__``.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from importlib.metadata import PackageMetadata, metadata

from flext_core import FlextVersion


class FlextAuthVersion(FlextVersion):
    """flext-auth version — MRO-derived from FlextVersion."""

    _metadata: PackageMetadata = metadata("flext-auth")


__version__ = FlextAuthVersion.__version__
__version_info__ = FlextAuthVersion.__version_info__
__title__ = FlextAuthVersion.__title__
__description__ = FlextAuthVersion.__description__
__author__ = FlextAuthVersion.__author__
__author_email__ = FlextAuthVersion.__author_email__
__license__ = FlextAuthVersion.__license__
__url__ = FlextAuthVersion.__url__
__all__: list[str] = [
    "FlextAuthVersion",
    "__author__",
    "__author_email__",
    "__description__",
    "__license__",
    "__title__",
    "__url__",
    "__version__",
    "__version_info__",
]

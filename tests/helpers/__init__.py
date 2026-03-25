# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make codegen
#
"""Test helpers for flext-auth tests.

Provides reusable test utilities and helpers for all test modules.
Consolidates typings, models, and protocols in unified classes.

Uses standardized short names (m, t, p, u) for easy access in tests.
Helpers extend main classes and use same short names in place of base classes.

NOTE: Constants have been moved to tests/constants.py - import from tests.constants instead.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import Mapping, MutableMapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr


if TYPE_CHECKING:
    from flext_core import FlextTypes
    from tests.helpers.protocols import TestsProtocols, p
    from tests.helpers.typings import TestsTypings, t
    from tests.helpers.utilities import TestsUtilities, u

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestsProtocols": ["tests.helpers.protocols", "TestsProtocols"],
    "TestsTypings": ["tests.helpers.typings", "TestsTypings"],
    "TestsUtilities": ["tests.helpers.utilities", "TestsUtilities"],
    "p": ["tests.helpers.protocols", "p"],
    "t": ["tests.helpers.typings", "t"],
    "u": ["tests.helpers.utilities", "u"],
}

__all__ = [
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "p",
    "t",
    "u",
]


_LAZY_CACHE: MutableMapping[str, FlextTypes.ModuleExport] = {}


def __getattr__(name: str) -> FlextTypes.ModuleExport:
    """Lazy-load module attributes on first access (PEP 562).

    A local cache ``_LAZY_CACHE`` persists resolved objects across repeated
    accesses during process lifetime.

    Args:
        name: Attribute name requested by dir()/import.

    Returns:
        Lazy-loaded module export type.

    Raises:
        AttributeError: If attribute not registered.
    """
    if name in _LAZY_CACHE:
        return _LAZY_CACHE[name]

    value = lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)
    _LAZY_CACHE[name] = value
    return value


def __dir__() -> Sequence[str]:
    """Return list of available attributes for dir() and autocomplete.

    Returns:
        List of public names from module exports.
    """
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)
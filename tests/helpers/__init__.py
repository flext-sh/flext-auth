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

from typing import TYPE_CHECKING, Any

from flext_core.lazy import cleanup_submodule_namespace, lazy_getattr

if TYPE_CHECKING:
    from protocols import TestsProtocols, TestsProtocols as p
    from typings import TestsTypings, t
    from utilities import TestsUtilities, TestsUtilities as u

# Lazy import mapping: export_name -> (module_path, attr_name)
_LAZY_IMPORTS: dict[str, tuple[str, str]] = {
    "TestsProtocols": ("protocols", "TestsProtocols"),
    "TestsTypings": ("typings", "TestsTypings"),
    "TestsUtilities": ("utilities", "TestsUtilities"),
    "p": ("protocols", "TestsProtocols"),
    "t": ("typings", "t"),
    "u": ("utilities", "TestsUtilities"),
}

__all__ = [
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "p",
    "t",
    "u",
]


def __getattr__(name: str) -> Any:  # noqa: ANN401
    """Lazy-load module attributes on first access (PEP 562)."""
    return lazy_getattr(name, _LAZY_IMPORTS, globals(), __name__)


def __dir__() -> list[str]:
    """Return list of available attributes for dir() and autocomplete."""
    return sorted(__all__)


cleanup_submodule_namespace(__name__, _LAZY_IMPORTS)

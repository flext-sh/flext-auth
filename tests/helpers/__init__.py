# AUTO-GENERATED FILE — DO NOT EDIT MANUALLY.
# Regenerate with: make gen
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

from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if TYPE_CHECKING:
    from tests.helpers import (
        protocols as protocols,
        typings as typings,
        utilities as utilities,
    )
    from tests.helpers.protocols import TestsProtocols as TestsProtocols, p as p
    from tests.helpers.typings import TestsTypings as TestsTypings, t as t
    from tests.helpers.utilities import TestsUtilities as TestsUtilities, u as u

_LAZY_IMPORTS: Mapping[str, Sequence[str]] = {
    "TestsProtocols": ["tests.helpers.protocols", "TestsProtocols"],
    "TestsTypings": ["tests.helpers.typings", "TestsTypings"],
    "TestsUtilities": ["tests.helpers.utilities", "TestsUtilities"],
    "p": ["tests.helpers.protocols", "p"],
    "protocols": ["tests.helpers.protocols", ""],
    "t": ["tests.helpers.typings", "t"],
    "typings": ["tests.helpers.typings", ""],
    "u": ["tests.helpers.utilities", "u"],
    "utilities": ["tests.helpers.utilities", ""],
}

_EXPORTS: Sequence[str] = [
    "TestsProtocols",
    "TestsTypings",
    "TestsUtilities",
    "p",
    "protocols",
    "t",
    "typings",
    "u",
    "utilities",
]


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS, _EXPORTS)

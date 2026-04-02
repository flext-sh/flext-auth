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
from typing import TYPE_CHECKING as _TYPE_CHECKING

from flext_core.lazy import install_lazy_exports

if _TYPE_CHECKING:
    from flext_core import FlextTypes
    from tests.helpers import protocols, typings, utilities
    from tests.helpers.protocols import TestsProtocols, p
    from tests.helpers.typings import TestsTypings, t
    from tests.helpers.utilities import TestsUtilities, u

_LAZY_IMPORTS: FlextTypes.LazyImportIndex = {
    "TestsProtocols": "tests.helpers.protocols",
    "TestsTypings": "tests.helpers.typings",
    "TestsUtilities": "tests.helpers.utilities",
    "p": "tests.helpers.protocols",
    "protocols": "tests.helpers.protocols",
    "t": "tests.helpers.typings",
    "typings": "tests.helpers.typings",
    "u": "tests.helpers.utilities",
    "utilities": "tests.helpers.utilities",
}


install_lazy_exports(__name__, globals(), _LAZY_IMPORTS)

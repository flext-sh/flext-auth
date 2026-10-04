"""FLEXT Auth registry over the canonical core registry DSL.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth import t
from flext_auth._registry.mutation import FlextAuthRegistryMutation


class FlextAuthRegistry(FlextAuthRegistryMutation):
    """Auth provider registry backed by the canonical registry DSL."""


__all__: t.MutableSequenceOf[str] = ["FlextAuthRegistry"]

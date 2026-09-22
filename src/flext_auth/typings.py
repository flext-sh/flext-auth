"""FLEXT Auth Types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import t

from ._typings.auth import FlextAuthTypesAuth
from ._typings.base import FlextAuthTypesBase


class FlextAuthTypes(t):
    """Authentication-specific type definitions extending t via MRO."""

    class Auth(FlextAuthTypesBase, FlextAuthTypesAuth):
        """Auth domain namespace (flat members per AGENTS.md §149)."""


t = FlextAuthTypes

__all__: list[str] = ["FlextAuthTypes", "t"]

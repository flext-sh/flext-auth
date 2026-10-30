# AUTO-GENERATED FILE — Regenerate with: make gen
"""FLEXT Auth Types.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import t

from flext_auth._typings import FlextAuthTypesAuth, FlextAuthTypesBase


class FlextAuthTypes(t):
    """Authentication-specific type definitions extending t via MRO."""

    class Auth(FlextAuthTypesAuth, FlextAuthTypesBase):
        """Auth domain namespace (flat members per AGENTS.md §149)."""


t = FlextAuthTypes
__all__: list[str] = ["FlextAuthTypes", "t"]

"""FLEXT Auth registry over the canonical core registry DSL.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from collections.abc import MutableSequence

from flext_auth._registry import FlextAuthRegistryMutation


class FlextAuthRegistry(FlextAuthRegistryMutation):
    """Auth provider registry backed by the canonical registry DSL."""


__all__: MutableSequence[str] = ["FlextAuthRegistry"]

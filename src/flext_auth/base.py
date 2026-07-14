"""Shared service base for flext-auth components.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC

from flext_auth import t
from flext_core import s


class FlextAuthServiceBase(s[bool], ABC):
    """Base class for auth services with typed configuration access."""


s = FlextAuthServiceBase

__all__: t.MutableSequenceOf[str] = ["FlextAuthServiceBase", "s"]

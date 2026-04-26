"""Shared service base for flext-auth components.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from typing import override

from flext_auth import FlextAuthSettings, t
from flext_core import FlextSettings, s


class FlextAuthServiceBase(s[bool], ABC):
    """Base class for auth services with typed configuration access."""

    @property
    @override
    def settings(self) -> FlextAuthSettings:
        """Return the typed auth settings namespace."""
        return FlextSettings.fetch_global().fetch_namespace("auth", FlextAuthSettings)


s = FlextAuthServiceBase

__all__: t.MutableSequenceOf[str] = ["FlextAuthServiceBase", "s"]

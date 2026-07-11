"""Shared service base for flext-auth components.

Copyright (c) 2025 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from abc import ABC
from typing import override

from flext_auth import FlextAuthSettings, m, t
from flext_core import s


class FlextAuthServiceBase(s[bool], ABC):
    """Base class for auth services with typed configuration access."""

    _auth_config: FlextAuthSettings = m.PrivateAttr(
        default_factory=lambda: FlextAuthSettings.model_validate({}),
    )

    @property
    @override
    def settings(self) -> FlextAuthSettings:
        """Typed auth settings namespace."""
        return self._auth_config


s = FlextAuthServiceBase

__all__: t.MutableSequenceOf[str] = ["FlextAuthServiceBase", "s"]

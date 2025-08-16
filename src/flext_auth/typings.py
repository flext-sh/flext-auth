"""Centralized typings facade for flext-auth."""

from __future__ import annotations

from flext_core import E, F, FlextTypes as CoreFlextTypes, P, R, T, U, V


class FlextTypes(CoreFlextTypes):
    """Auth domain-specific types can extend here."""


__all__ = [
    "E",
    "F",
    "FlextTypes",
    "P",
    "R",
    "T",
    "U",
    "V",
]

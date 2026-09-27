"""FLEXT Auth registry over the canonical core registry DSL."""

from __future__ import annotations

from flext_auth import t

from ._registry.mutation import FlextAuthRegistryMutation


class FlextAuthRegistry(FlextAuthRegistryMutation):
    """Auth provider registry backed by the canonical registry DSL."""


__all__: t.MutableSequenceOf[str] = ["FlextAuthRegistry"]

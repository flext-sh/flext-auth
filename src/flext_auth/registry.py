"""FLEXT Auth registry over the canonical core registry DSL."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_auth._registry.metadata import FlextAuthRegistryMetadata

if TYPE_CHECKING:
    from flext_auth import t


class FlextAuthRegistry(FlextAuthRegistryMetadata):
    """Auth provider registry backed by the canonical registry DSL."""


__all__: t.MutableSequenceOf[str] = ["FlextAuthRegistry"]

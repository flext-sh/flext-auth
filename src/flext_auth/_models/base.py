"""FlextAuth models base — foundational models owner of the private family."""

from __future__ import annotations


class FlextAuthModelsBase:
    """Base and foundational owner of the FlextAuth private models family.

    Every composed ``FlextAuthModels*`` owner inherits from this base, so the
    family MRO is explicit and the domain namespace composes all owners
    through multiple inheritance.
    """


__all__: list[str] = ["FlextAuthModelsBase"]

"""FlextAuth utilities base — foundational utilities owner of the private family."""

from __future__ import annotations


class FlextAuthUtilitiesBase:
    """Base and foundational owner of the FlextAuth private utilities family.

    Every composed ``FlextAuthUtilities*`` owner inherits from this base, so
    the family MRO is explicit and the domain namespace composes all owners
    through multiple inheritance.
    """


__all__: list[str] = ["FlextAuthUtilitiesBase"]

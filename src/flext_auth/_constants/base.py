"""FlextAuth constants base — foundational constants owner of the private family."""

from __future__ import annotations


class FlextAuthConstantsBase:
    """Base and foundational owner of the FlextAuth private constants family.

    Every composed ``FlextAuthConstants*`` owner inherits from this base, so
    the family MRO is explicit and the domain namespace composes all owners
    through multiple inheritance.
    """


__all__: list[str] = ["FlextAuthConstantsBase"]

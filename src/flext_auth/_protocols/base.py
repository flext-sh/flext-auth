"""FlextAuth protocols base — foundational contracts owner of the private family."""

from __future__ import annotations


class FlextAuthProtocolsBase:
    """Base and foundational owner of the FlextAuth private protocols family.

    Every composed ``FlextAuthProtocols*`` owner inherits from this base, so
    the family MRO is explicit and the domain namespace composes all owners
    through multiple inheritance.
    """


__all__: list[str] = ["FlextAuthProtocolsBase"]

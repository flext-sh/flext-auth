"""Authentication constants namespace."""

from __future__ import annotations

from flext_auth._constants.auth_values import FlextAuthConstantsAuthValues


class FlextAuthConstantsAuth(FlextAuthConstantsAuthValues):
    """Authentication constants namespace assembled from focused owners."""


__all__: list[str] = ["FlextAuthConstantsAuth"]

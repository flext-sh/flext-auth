"""Authentication constants namespace values."""

from __future__ import annotations

from flext_auth._constants.auth_security import FlextAuthConstantsAuthSecurity


class FlextAuthConstantsAuthValues(FlextAuthConstantsAuthSecurity):
    """Complete authentication constants namespace."""


__all__: list[str] = ["FlextAuthConstantsAuthValues"]

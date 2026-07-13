"""FlextAuth utilities facade."""

from __future__ import annotations

from flext_api import u

from flext_auth import t
from flext_auth._utilities.auth import FlextAuthUtilitiesAuth
from flext_auth._utilities.managers import FlextAuthUtilitiesManagers


class FlextAuthUtilities(u):
    """FlextAuth advanced utilities extending the API utility namespace."""

    class Auth(FlextAuthUtilitiesAuth, FlextAuthUtilitiesManagers):
        """Auth-specific utility namespace."""


u = FlextAuthUtilities

__all__: t.MutableSequenceOf[str] = ["FlextAuthUtilities", "u"]

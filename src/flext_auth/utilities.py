"""FlextAuth utilities facade."""

from __future__ import annotations

from flext_api import FlextApiUtilities

from flext_auth import t

from ._utilities.auth import FlextAuthUtilitiesAuth
from ._utilities.identity_audit import FlextAuthIdentityAudit
from ._utilities.managers import FlextAuthUtilitiesManagers


class FlextAuthUtilities(FlextApiUtilities):
    """FlextAuth advanced utilities extending the API utility namespace."""

    class Auth(FlextAuthUtilitiesAuth, FlextAuthUtilitiesManagers):
        """Auth-specific utility namespace."""


u = FlextAuthUtilities

__all__: t.MutableSequenceOf[str] = [
    "FlextAuthIdentityAudit",
    "FlextAuthUtilities",
    "u",
]

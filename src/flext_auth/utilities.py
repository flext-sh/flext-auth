"""FlextAuth utilities facade."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_api import FlextApiUtilities

from flext_auth._utilities.auth import FlextAuthUtilitiesAuth
from flext_auth._utilities.managers import FlextAuthUtilitiesManagers
from flext_core import FlextUtilitiesGuardsTypeCore, FlextUtilitiesModelRuntime

if TYPE_CHECKING:
    from flext_auth import t


class FlextAuthUtilities(
    FlextApiUtilities,
    FlextUtilitiesGuardsTypeCore,
    FlextUtilitiesModelRuntime,
    FlextAuthUtilitiesAuth,
    FlextAuthUtilitiesManagers,
):
    """FlextAuth advanced utilities extending the API utility namespace."""

    class Auth(FlextAuthUtilitiesAuth):
        """Auth-specific utility namespace."""


u = FlextAuthUtilities

__all__: t.MutableSequenceOf[str] = ["FlextAuthUtilities", "u"]

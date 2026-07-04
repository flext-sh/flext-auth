"""FlextAuth constants facade."""

from __future__ import annotations

from flext_api import c

from flext_auth import t
from flext_auth._constants.auth import FlextAuthConstantsAuth


class FlextAuthConstants(
    c,
    FlextAuthConstantsAuth,
):
    """FlextAuth domain constants extending the API constants namespace."""

    class Auth(FlextAuthConstantsAuth):
        """Authentication constants namespace."""


c = FlextAuthConstants

__all__: t.MutableSequenceOf[str] = ["FlextAuthConstants", "c"]

"""FlextAuth constants facade."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_api import c

from ._constants.auth import FlextAuthConstantsAuth
from ._constants.base import FlextAuthConstantsBase

if TYPE_CHECKING:
    from flext_auth import t


class FlextAuthConstants(c):
    """FlextAuth domain constants extending the API constants namespace."""

    class Auth(FlextAuthConstantsBase, FlextAuthConstantsAuth):
        """Authentication constants namespace."""


c = FlextAuthConstants

__all__: t.MutableSequenceOf[str] = ["FlextAuthConstants", "c"]

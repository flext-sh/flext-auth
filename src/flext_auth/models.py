"""FLEXT Auth models facade."""

from __future__ import annotations

from flext_api import m

from flext_auth import t
from flext_auth._models.auth import FlextAuthModelsAuth


class FlextAuthModels(
    m,
    FlextAuthModelsAuth,
):
    """Authentication models extending the API model namespace."""

    class Auth(FlextAuthModelsAuth):
        """Authentication model namespace."""


m = FlextAuthModels

__all__: t.MutableSequenceOf[str] = ["FlextAuthModels", "m"]

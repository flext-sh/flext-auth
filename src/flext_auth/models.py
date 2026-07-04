"""FLEXT Auth models facade."""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_api import m

from flext_auth._models.auth import FlextAuthModelsAuth

if TYPE_CHECKING:
    from flext_auth import t


class FlextAuthModels(
    m,
    FlextAuthModelsAuth,
):
    """Authentication models extending the API model namespace."""

    class Auth(FlextAuthModelsAuth):
        """Authentication model namespace."""


m = FlextAuthModels

__all__: t.MutableSequenceOf[str] = ["FlextAuthModels", "m"]

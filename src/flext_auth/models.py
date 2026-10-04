"""FLEXT Auth models facade.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_api import FlextApiModels

from flext_auth import t
from flext_auth._models.auth import FlextAuthModelsAuth
from flext_auth._models.base import FlextAuthModelsBase


class FlextAuthModels(FlextApiModels):
    """Authentication models extending the API model namespace."""

    class Auth(FlextAuthModelsBase, FlextAuthModelsAuth):
        """Authentication model namespace."""


m = FlextAuthModels

__all__: t.MutableSequenceOf[str] = ["FlextAuthModels", "m"]

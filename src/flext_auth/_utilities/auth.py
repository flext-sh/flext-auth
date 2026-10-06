"""Authentication utility namespace.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from flext_auth._utilities.auth_response import FlextAuthUtilitiesAuthResponse
from flext_auth._utilities.auth_session import FlextAuthUtilitiesAuthSession
from flext_auth._utilities.auth_validation import FlextAuthUtilitiesAuthValidation


class FlextAuthUtilitiesAuth(
    FlextAuthUtilitiesAuthValidation,
    FlextAuthUtilitiesAuthResponse,
    FlextAuthUtilitiesAuthSession,
):
    """Authentication utility namespace assembled from focused owners."""


__all__: list[str] = ["FlextAuthUtilitiesAuth"]

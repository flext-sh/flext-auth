"""Authentication utility namespace."""

from __future__ import annotations

from .auth_response import FlextAuthUtilitiesAuthResponse
from .auth_token import FlextAuthUtilitiesAuthToken
from .auth_validation import FlextAuthUtilitiesAuthValidation


class FlextAuthUtilitiesAuth(
    FlextAuthUtilitiesAuthValidation,
    FlextAuthUtilitiesAuthResponse,
    FlextAuthUtilitiesAuthToken,
):
    """Authentication utility namespace assembled from focused owners."""


__all__: list[str] = ["FlextAuthUtilitiesAuth"]

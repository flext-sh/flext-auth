"""Authentication utility namespace."""

from __future__ import annotations

from flext_auth._utilities.auth_response import FlextAuthUtilitiesAuthResponse
from flext_auth._utilities.auth_token import FlextAuthUtilitiesAuthToken
from flext_auth._utilities.auth_validation import FlextAuthUtilitiesAuthValidation


class FlextAuthUtilitiesAuth(
    FlextAuthUtilitiesAuthValidation,
    FlextAuthUtilitiesAuthResponse,
    FlextAuthUtilitiesAuthToken,
):
    """Authentication utility namespace assembled from focused owners."""


__all__: list[str] = ["FlextAuthUtilitiesAuth"]

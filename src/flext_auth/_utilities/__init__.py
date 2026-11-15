# AUTO-GENERATED FILE — Regenerate with: make gen
"""Flext Auth. Utilities package.

Copyright (c) 2026 FLEXT Team. All rights reserved.
SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from flext_core.lazy import defer_lazy_bases, install_lazy_exports

if TYPE_CHECKING:
    from flext_auth._utilities.auth import FlextAuthUtilitiesAuth
    from flext_auth._utilities.auth_response import FlextAuthUtilitiesAuthResponse
    from flext_auth._utilities.auth_session import FlextAuthUtilitiesAuthSession
    from flext_auth._utilities.auth_validation import FlextAuthUtilitiesAuthValidation
    from flext_auth._utilities.base import FlextAuthUtilitiesBase
    from flext_auth._utilities.managers import FlextAuthUtilitiesManagers


__all__: tuple[str, ...] = (
    "FlextAuthUtilitiesAuth",
    "FlextAuthUtilitiesAuthResponse",
    "FlextAuthUtilitiesAuthSession",
    "FlextAuthUtilitiesAuthValidation",
    "FlextAuthUtilitiesBase",
    "FlextAuthUtilitiesManagers",
)

install_lazy_exports(
    __name__,
    globals(),
    {
        "FlextAuthUtilitiesAuth": ".auth",
        "FlextAuthUtilitiesAuthResponse": ".auth_response",
        "FlextAuthUtilitiesAuthSession": ".auth_session",
        "FlextAuthUtilitiesAuthValidation": ".auth_validation",
        "FlextAuthUtilitiesBase": ".base",
        "FlextAuthUtilitiesManagers": ".managers",
    },
    public_exports=__all__,
    deferred_members={
        "FlextAuthUtilitiesAuth": (),
        "FlextAuthUtilitiesAuthResponse": (
            "build_auth_error_response",
            "build_auth_success_response",
        ),
        "FlextAuthUtilitiesAuthSession": (
            "decode_token",
            "encode_token",
        ),
        "FlextAuthUtilitiesAuthValidation": (
            "validate_email",
            "validate_password",
            "validate_username",
            "calculate_expiry_time",
            "generate_session_id",
            "expired",
            "hash_password",
            "verify_password",
        ),
        "FlextAuthUtilitiesManagers": (),
    },
)

defer_lazy_bases(
    __name__,
    {
        "FlextAuthUtilitiesAuth": (
            (".", "FlextAuthUtilitiesAuthValidation"),
            (".", "FlextAuthUtilitiesAuthResponse"),
            (".", "FlextAuthUtilitiesAuthSession"),
        ),
        "FlextAuthUtilitiesManagers": (
            ("flext_auth._utilities._managers", "FlextAuthSessionManagers"),
            ("flext_auth._utilities._managers", "FlextAuthRateLimiterManagers"),
            ("flext_auth._utilities._managers", "FlextAuthUserManagers"),
        ),
    },
)

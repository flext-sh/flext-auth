"""FLEXT Auth Helpers - Current API helper functions.

Copyright (c) 2025 Flext. All rights reserved.
SPDX-License-Identifier: MIT

"""

# Helper functions using main API
from flext_auth.api import (
    flext_auth_generate_jwt,
    flext_auth_hash_password,
    flext_auth_quick_start,
    flext_auth_validate_email,
    flext_auth_validate_jwt,
    flext_auth_validate_password_strength,
    flext_auth_verify_password,
    generate_secure_password,
    generate_secure_token,
    get_utc_now,
    is_strong_password,
    mask_sensitive_data,
)

__all__ = [
    "flext_auth_generate_jwt",
    "flext_auth_hash_password",
    "flext_auth_quick_start",
    "flext_auth_validate_email",
    "flext_auth_validate_jwt",
    "flext_auth_validate_password_strength",
    "flext_auth_verify_password",
    "generate_secure_password",
    "generate_secure_token",
    "get_utc_now",
    "is_strong_password",
    "mask_sensitive_data",
]

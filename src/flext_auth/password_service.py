"""Legacy compatibility facade for password_service.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

This module is deprecated. Use 'flext_auth.password' instead.
"""

# Legacy compatibility facade
import warnings

from flext_auth.password import *  # noqa: F403,F401

warnings.warn(
    "password_service module is deprecated, use 'flext_auth.password' instead",
    DeprecationWarning,
    stacklevel=2,
)

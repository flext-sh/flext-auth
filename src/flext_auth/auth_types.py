"""Legacy compatibility facade for auth_types.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

This module is deprecated. Content moved to 'flext_auth.types'.
"""

# Legacy compatibility facade
import warnings

from flext_auth.types import TEmail, TPassword, TUsername  # noqa: F401

warnings.warn(
    "auth_types module is deprecated, use 'flext_auth.types' instead",
    DeprecationWarning,
    stacklevel=2,
)

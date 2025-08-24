"""Legacy compatibility facade for value_objects.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

This module is deprecated. Use 'flext_auth.values' instead.
"""

# Legacy compatibility facade
import warnings

from flext_auth.values import *  # noqa: F403,F401

warnings.warn(
    "value_objects module is deprecated, use 'flext_auth.values' instead",
    DeprecationWarning,
    stacklevel=2,
)

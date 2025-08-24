"""Legacy compatibility facade for repositories_simple.

Copyright (c) 2025 FLEXT Contributors
SPDX-License-Identifier: MIT

This module is deprecated. Use 'flext_auth.repositories' instead.
"""

# Legacy compatibility facade
import warnings

from flext_auth.repositories import *  # noqa: F403,F401

warnings.warn(
    "repositories_simple module is deprecated, use 'flext_auth.repositories' instead",
    DeprecationWarning,
    stacklevel=2,
)
